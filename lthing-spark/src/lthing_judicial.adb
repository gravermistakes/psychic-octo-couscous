------------------------------------------------------------------------------
--  LTHING.Judicial (body) — fail-closed .jd.lthing verification
--
--  Verifies a complete LTHING envelope per LTHING_HEADER_SPEC.md:
--    §2  14-byte magic prefix (preamble + JD doctype + non-zero version)
--    §3  40-byte fixed header (crypto suite, timestamp, section lengths)
--    §5  provenance seal (ancestor, artifact hash, chain hash, relation,
--        signer id, seal id)
--    §6  ML-DSA-65 signature over header ‖ body ‖ seal
--    §9  the MUST-gate parser requirements (fail-closed at the first failure)
--
--  Result starts (Not_Verified, False); Trusted becomes True in exactly ONE
--  place, only after every §9 gate has passed. Every failure path assigns a
--  specific Status and returns immediately with Trusted = False (the type
--  predicate keeps the two consistent). This is the safe inverse of audit
--  FINDING-002 ("signature stub returns True"): any doubt rejects.
--
--  The §3 byte layout is the in-repo source of truth (LTHING_HEADER_SPEC.md),
--  not a fictional external dependency.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;    use Interfaces;   --  bitwise or/xor on Byte; Unsigned_*
with LTHING_Keccak;
with LTHING_MLDSA65;
with LTHING_MLDSA87;

package body LTHING_Judicial is

   ---------------------------------------------------------------------------
   --  Fixed format constants (LTHING_HEADER_SPEC.md).
   ---------------------------------------------------------------------------

   --  §2.1 preamble (bytes 0..9), §2.2/§2.5 JD doctype block (bytes 10..12).
   Preamble : constant Byte_Array (0 .. 9) :=
     (16#00#, 16#00#, 16#00#, 16#0B#, 16#0D#, 16#EE#, 16#D0#,
      16#00#, 16#00#, 16#00#);
   JD_DocType_B10 : constant := 16#04#;     --  offset nibble | 'J' hi
   JD_DocType_B11 : constant := 16#A4#;     --  'J' lo | 'D' hi
   JD_DocType_B12 : constant := 16#40#;     --  'D' lo | null terminator

   --  §3 header geometry (all section lengths live in the 40-byte header).
   Header_Bytes  : constant := 40;
   Suite_Off     : constant := 14;          --  2 B  crypto suite selector
   Body_Len_Off  : constant := 24;          --  4 B  body length
   Seal_Len_Off  : constant := 28;          --  4 B  provenance seal length
   Sig_Len_Off   : constant := 32;          --  4 B  signature length
   Aead_Len_Off  : constant := 36;          --  4 B  AEAD tag length

   Suite_Baseline : constant := 16#0001#;   --  ML-DSA-65 baseline (NIST L3)
   Suite_MLDSA87  : constant := 16#0002#;  --  ML-DSA-87 (NSS / CNSA 2.0, NIST L5)

   --  §5.1 seal field widths for suite 0x0001 (ArtifactHash = 64).
   Hash_Bytes    : constant := 64;          --  LTHING SHAKE512 digest
   --  min seal = ancestor(2)+artifact(64)+chain(64)+relation(1)
   --             +signerlen(1)+signer(0)+sealid(64) = 196
   Min_Seal_Bytes : constant := 2 + Hash_Bytes + Hash_Bytes + 1 + 1 + Hash_Bytes;

   ---------------------------------------------------------------------------
   --  Internal helpers (all pure, all fail-closed).
   ---------------------------------------------------------------------------

   --  Envelope shape: must at least carry the fixed 40-byte header.
   function Envelope_Ok (Document : Byte_Array) return Boolean
     with Global => null,
          Post => Envelope_Ok'Result = (Document'Length >= Header_Bytes)
   is
   begin
      return Document'Length >= Header_Bytes;
   end Envelope_Ok;

   --  Magic / doctype / version gate (§2). Validates the exact 10-byte
   --  preamble, the JD doctype block (bytes 10..12 = 04 A4 40), and that the
   --  version byte (byte 13, §2.4) is non-zero (0x00 is RESERVED → reject).
   function Magic_Ok (Document : Byte_Array) return Boolean
     with Global => null
   is
   begin
      if Document'Length < Header_Bytes then
         return False;
      end if;
      for I in Preamble'Range loop
         if Document (Document'First + I) /= Preamble (I) then
            return False;
         end if;
      end loop;
      return Document (Document'First + 10) = JD_DocType_B10
        and then Document (Document'First + 11) = JD_DocType_B11
        and then Document (Document'First + 12) = JD_DocType_B12
        and then Document (Document'First + 13) /= 16#00#;
   end Magic_Ok;

   --  Big-endian readers. Preconditions keep every index in bounds; the
   --  results are widened so the length arithmetic cannot overflow.
   function Read_U16 (D : Byte_Array; Off : Index_Range) return Unsigned_16
     with Global => null,
          Pre => Off >= D'First and then Off < D'Last
   is
   begin
      return Unsigned_16 (D (Off)) * 256 + Unsigned_16 (D (Off + 1));
   end Read_U16;

   function Read_U32 (D : Byte_Array; Off : Index_Range) return Unsigned_64
     with Global => null,
          Pre  => Off >= D'First and then Off + 3 <= D'Last,
          Post => Read_U32'Result <= 16#FFFF_FFFF#
   is
   begin
      return Unsigned_64 (D (Off))     * 16#01_00_00_00#
           + Unsigned_64 (D (Off + 1)) * 16#01_00_00#
           + Unsigned_64 (D (Off + 2)) * 16#01_00#
           + Unsigned_64 (D (Off + 3));
   end Read_U32;

   --  LTHING "SHAKE512": Sponge(rate 72, domain 0x1F, 64-byte output).
   function LTHING_SHAKE512 (Input : Byte_Array) return Digest
     with Global => null
   is
      Buf : Byte_Array (0 .. 63) := (others => 0);
      R   : Digest := (others => 0);
   begin
      LTHING_Keccak.Sponge
        (Input  => Input,
         Rate   => LTHING_Keccak.Rate_SHA3_512,
         Domain => LTHING_Keccak.Domain_SHAKE,
         Output => Buf);
      for I in Digest_Index loop
         R (I) := Buf (I);
      end loop;
      return R;
   end LTHING_SHAKE512;

   --  Compare a computed digest H against the 64-byte window D(Off .. Off+63),
   --  constant-time over the 64 bytes.
   function Window_Equal
     (H : Digest; D : Byte_Array; Off : Index_Range) return Boolean
     with Global => null,
          Pre => Off >= D'First and then Off + (Hash_Bytes - 1) <= D'Last
   is
      Acc : Byte := 0;
   begin
      for I in 0 .. Hash_Bytes - 1 loop
         Acc := Acc or (H (I) xor D (Off + I));
      end loop;
      return Acc = 0;
   end Window_Equal;

   ---------------------------------------------------------------------------
   --  Parse_Unverified — structural only, never trusted.
   ---------------------------------------------------------------------------
   procedure Parse_Unverified
     (Document : Byte_Array;
      Result   : out Verified_Record)
   is
   begin
      if not Envelope_Ok (Document) then
         Result := (Status => Bad_Envelope, Trusted => False);
      else
         --  Structure recognized, but this entry point grants NO trust.
         Result := (Status => Not_Verified, Trusted => False);
      end if;
   end Parse_Unverified;

   ---------------------------------------------------------------------------
   --  Parse_And_Verify — full §9 gate; Trusted set once, at the very end.
   ---------------------------------------------------------------------------
   procedure Parse_And_Verify
     (Document      : Byte_Array;
      Previous_Seal : Digest;
      Public_Key    : Byte_Array;
      Result        : out Verified_Record)
   is
      F : constant Index_Range := Document'First;
   begin
      Result := (Status => Not_Verified, Trusted => False);

      --  §9.1 (+shape): at least the fixed 40-byte header.
      if not Envelope_Ok (Document) then
         Result := (Status => Bad_Envelope, Trusted => False);
         return;
      end if;

      --  §9.1/§9.2: preamble, JD doctype, non-zero version.
      if not Magic_Ok (Document) then
         Result := (Status => Bad_Magic, Trusted => False);
         return;
      end if;

      --  At this point Document'Length >= 40, so F + 39 <= Document'Last and
      --  every header read below is in bounds.
      pragma Assert (Document'Length >= Header_Bytes);
      declare
         Suite    : constant Unsigned_16 := Read_U16 (Document, F + Suite_Off);
         Is_87    : constant Boolean := Suite = Suite_MLDSA87;
         Exp_SigB : constant Natural :=
           (if Is_87 then LTHING_MLDSA87.Sig_Bytes
                     else LTHING_MLDSA65.Sig_Bytes);
         Exp_PKB  : constant Natural :=
           (if Is_87 then LTHING_MLDSA87.PK_Bytes
                     else LTHING_MLDSA65.PK_Bytes);
         BL    : constant Unsigned_64 := Read_U32 (Document, F + Body_Len_Off);
         SL    : constant Unsigned_64 := Read_U32 (Document, F + Seal_Len_Off);
         SigL  : constant Unsigned_64 := Read_U32 (Document, F + Sig_Len_Off);
         AeadL : constant Unsigned_64 := Read_U32 (Document, F + Aead_Len_Off);
         Total : constant Unsigned_64 :=
           Unsigned_64 (Header_Bytes) + BL + SL + SigL + AeadL;
      begin
         --  §9.3/§9.4: seal and signature lengths must be non-zero.
         if SL = 0 or else SigL = 0 then
            Result := (Status => Bad_Length, Trusted => False);
            return;
         end if;

         --  §3.1: suite 0x0001 (ML-DSA-65) and 0x0002 (ML-DSA-87 / CNSA 2.0)
         --  are accepted; 0x0000 is RESERVED and all other values are unknown.
         if Suite /= Suite_Baseline and then Suite /= Suite_MLDSA87 then
            Result := (Status => Bad_Length, Trusted => False);
            return;
         end if;

         --  The suite fixes the signature length and forbids AEAD in both cases.
         if SigL /= Unsigned_64 (Exp_SigB) or else AeadL /= 0 then
            Result := (Status => Bad_Length, Trusted => False);
            return;
         end if;

         --  §9.5: declared sections must exactly account for the bytes on the
         --  wire (no overflow, no trailing slack) for the baseline suite.
         if Total /= Unsigned_64 (Document'Length) then
            Result := (Status => Bad_Length, Trusted => False);
            return;
         end if;

         --  Trusted PK must match the suite's public-key size.
         if Public_Key'Length /= Exp_PKB then
            Result := (Status => Bad_Length, Trusted => False);
            return;
         end if;

         --  Total = Document'Length <= Max_Document_Bytes, so each cumulative
         --  offset below is a valid Index_Range value. Pin the bounds that the
         --  AoRTE checks on the offset arithmetic and length conversions need.
         pragma Assert (Total = Unsigned_64 (Document'Length));
         pragma Assert (BL <= Total);
         pragma Assert (SL <= Total);
         pragma Assert (BL + SL + SigL <= Total);
         declare
            Body_Len   : constant Natural := Natural (BL);
            Seal_Len   : constant Natural := Natural (SL);
            Body_Off   : constant Index_Range := F + Header_Bytes;
            Seal_Off   : constant Index_Range := Body_Off + Body_Len;
            Sig_Off    : constant Index_Range := Seal_Off + Seal_Len;
            Signed_Len : constant Natural := Header_Bytes + Body_Len + Seal_Len;
         begin
            --  Section geometry, all derived from Total = Document'Length:
            --  body/seal/signature fit exactly within the wire bytes.
            pragma Assert (Sig_Off + (Exp_SigB - 1) = Document'Last);
            pragma Assert (Sig_Off <= Document'Last);
            pragma Assert (Seal_Off <= Sig_Off);
            pragma Assert (Body_Off + Body_Len = Seal_Off);
            --  §6/§9.10: the ML-DSA Verify precondition caps the message
            --  length; an envelope whose signed prefix exceeds it is rejected
            --  rather than truncated.
            if Signed_Len > LTHING_MLDSA65.Max_Message_Bytes then
               Result := (Status => Bad_Length, Trusted => False);
               return;
            end if;

            --  §5.1: minimum seal size (signer id may be empty).
            if Seal_Len < Min_Seal_Bytes then
               Result := (Status => Bad_Length, Trusted => False);
               return;
            end if;

            --  The whole seal lies within [Seal_Off, Sig_Off-1] ⊆ document, so
            --  every fixed seal field (through offset Min_Seal_Bytes-1) is in
            --  bounds.
            pragma Assert (Seal_Off + Seal_Len = Sig_Off);
            pragma Assert (Seal_Off + (Min_Seal_Bytes - 1) <= Document'Last);

            declare
               Art_Off    : constant Index_Range := Seal_Off + 2;
               Chain_Off  : constant Index_Range := Art_Off + Hash_Bytes;
               Rel_Off    : constant Index_Range := Chain_Off + Hash_Bytes;
               SidLen_Off : constant Index_Range := Rel_Off + 1;
               Signer_Off : constant Index_Range := SidLen_Off + 1;
               Signer_Len : constant Natural :=
                 Natural (Document (SidLen_Off));
            begin
               --  §5: seal_len must equal 196 + signer_len exactly.
               if Seal_Len /= Min_Seal_Bytes + Signer_Len then
                  Result := (Status => Bad_Length, Trusted => False);
                  return;
               end if;

               --  With the exact seal length, the signer-id and seal-id fields
               --  end at Sig_Off-1, i.e. inside the document.
               pragma Assert (Signer_Off + Signer_Len + (Hash_Bytes - 1)
                              <= Document'Last);

               declare
                  Sealid_Off : constant Index_Range := Signer_Off + Signer_Len;
                  Ancestor   : constant Unsigned_16 :=
                    Read_U16 (Document, Seal_Off);
                  Relation   : constant Byte := Document (Rel_Off);
               begin
                  --  §9.6: ArtifactHash = LTHING_SHAKE512(body).
                  if not Window_Equal
                           (LTHING_SHAKE512
                              (Document (Body_Off .. Body_Off + Body_Len - 1)),
                            Document, Art_Off)
                  then
                     Result := (Status => Seal_Mismatch, Trusted => False);
                     return;
                  end if;

                  --  §9.9: GENESIS (Relation = 0x00) iff AncestorCount = 0.
                  if (Relation = 16#00#) /= (Ancestor = 0) then
                     Result := (Status => Seal_Mismatch, Trusted => False);
                     return;
                  end if;

                  --  §9.7: ChainHash = LTHING_SHAKE512(prev_chain ‖ artifact).
                  --  Genesis passes Previous_Seal = all-zero digest.
                  declare
                     CBuf : Byte_Array (0 .. 2 * Hash_Bytes - 1) :=
                       (others => 0);
                  begin
                     for I in 0 .. Hash_Bytes - 1 loop
                        CBuf (I) := Previous_Seal (I);
                     end loop;
                     for I in 0 .. Hash_Bytes - 1 loop
                        CBuf (Hash_Bytes + I) := Document (Art_Off + I);
                     end loop;
                     if not Window_Equal
                              (LTHING_SHAKE512 (CBuf), Document, Chain_Off)
                     then
                        Result := (Status => Chain_Broken, Trusted => False);
                        return;
                     end if;
                  end;

                  --  §9.8: SealId = LTHING_SHAKE512(ancestor ‖ artifact ‖
                  --  chain ‖ relation ‖ signer_id).
                  declare
                     SCnt : constant Natural :=
                       2 + Hash_Bytes + Hash_Bytes + 1 + Signer_Len;
                     SBuf : Byte_Array (0 .. 2 + 2 * Hash_Bytes + 1 + 255 - 1) :=
                       (others => 0);
                  begin
                     SBuf (0) := Document (Seal_Off);
                     SBuf (1) := Document (Seal_Off + 1);
                     for I in 0 .. Hash_Bytes - 1 loop
                        SBuf (2 + I) := Document (Art_Off + I);
                     end loop;
                     for I in 0 .. Hash_Bytes - 1 loop
                        SBuf (2 + Hash_Bytes + I) := Document (Chain_Off + I);
                     end loop;
                     SBuf (2 + 2 * Hash_Bytes) := Relation;
                     for I in 0 .. Signer_Len - 1 loop
                        SBuf (2 + 2 * Hash_Bytes + 1 + I) :=
                          Document (Signer_Off + I);
                     end loop;
                     if not Window_Equal
                              (LTHING_SHAKE512 (SBuf (0 .. SCnt - 1)),
                               Document, Sealid_Off)
                     then
                        Result := (Status => Seal_Mismatch, Trusted => False);
                        return;
                     end if;
                  end;

                  --  §9.10: ML-DSA signature over header ‖ body ‖ seal,
                  --  empty context (§7 design recommendation). Suite selects
                  --  ML-DSA-65 (0x0001) or ML-DSA-87 (0x0002).
                  declare
                     Empty : constant Byte_Array (1 .. 0) := (others => 0);
                     PKf   : constant Index_Range := Public_Key'First;
                  begin
                     if Is_87 then
                        declare
                           PKc : LTHING_MLDSA87.Public_Key := (others => 0);
                           Sgc : LTHING_MLDSA87.Signature  := (others => 0);
                        begin
                           for I in 0 .. LTHING_MLDSA87.PK_Bytes - 1 loop
                              PKc (I) := Public_Key (PKf + I);
                           end loop;
                           for I in 0 .. LTHING_MLDSA87.Sig_Bytes - 1 loop
                              Sgc (I) := Document (Sig_Off + I);
                           end loop;
                           if not LTHING_MLDSA87.Verify
                                    (PK      => PKc,
                                     Message => Document (F .. F + Signed_Len - 1),
                                     Context => Empty,
                                     Sig     => Sgc)
                           then
                              Result :=
                                (Status => Signature_Invalid, Trusted => False);
                              return;
                           end if;
                        end;
                     else
                        declare
                           PKc : LTHING_MLDSA65.Public_Key := (others => 0);
                           Sgc : LTHING_MLDSA65.Signature  := (others => 0);
                        begin
                           for I in 0 .. LTHING_MLDSA65.PK_Bytes - 1 loop
                              PKc (I) := Public_Key (PKf + I);
                           end loop;
                           for I in 0 .. LTHING_MLDSA65.Sig_Bytes - 1 loop
                              Sgc (I) := Document (Sig_Off + I);
                           end loop;
                           if not LTHING_MLDSA65.Verify
                                    (PK      => PKc,
                                     Message => Document (F .. F + Signed_Len - 1),
                                     Context => Empty,
                                     Sig     => Sgc)
                           then
                              Result :=
                                (Status => Signature_Invalid, Trusted => False);
                              return;
                           end if;
                        end;
                     end if;
                  end;

                  --  Every §9 gate passed: the ONLY place Trusted is True.
                  Result := (Status => Verified, Trusted => True);
               end;
            end;
         end;
      end;
   end Parse_And_Verify;

end LTHING_Judicial;
