------------------------------------------------------------------------------
--  LTHING.MLDSA.Sign (body) — FIPS 204 KeyGen_internal (Alg.6) + Sign_internal
--  (Alg.7). SPARK_Mode (On); AoRTE + flow. Fail-closed on loop exhaustion.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Keccak;       use LTHING_Keccak;
with LTHING_MLDSA_Field;
with LTHING_MLDSA_NTT;
with LTHING_MLDSA_Codec;
with LTHING_MLDSA_Round;
with LTHING_MLDSA_Sample;

package body LTHING_MLDSA_Sign is

   package Fld renames LTHING_MLDSA_Field;
   package Ntt renames LTHING_MLDSA_NTT;
   package Cod renames LTHING_MLDSA_Codec;
   package Rnd renames LTHING_MLDSA_Round;
   package Smp renames LTHING_MLDSA_Sample;

   use type Fld.Fq;

   subtype Fq is Fld.Fq;

   Max_Attempts : constant := 1000;   --  bounds the rejection loop (Alg.7)

   ---------------------------------------------------------------------------
   --  small helpers
   ---------------------------------------------------------------------------

   --  SHAKE256 XOF: Output'Length bytes of SHAKE256(Input).
   procedure Shake256 (Input : Byte_Array; Output : out Byte_Array)
     with Global => null, Pre => Output'Length > 0
   is
   begin
      Sponge (Input  => Input,
              Rate   => Rate_SHAKE256,
              Domain => Domain_SHAKE,
              Output => Output);
   end Shake256;

   --  Canonical Fq from a small centered value.
   function Canon (V : Integer_32) return Fq
     with Global => null, Pre => V in -(Q - 1) .. Q - 1
   is
   begin
      return (if V < 0 then V + Q else V);
   end Canon;

   --  SPoly (Fq) -> MLDSA65.Poly (Coeff); values copy unchanged (Fq subset).
   function To_M (P : SPoly) return Poly
     with Global => null,
          Post => (for all I in Poly'Range => To_M'Result (I) = P (I))
   is
      R : Poly := (others => 0);
   begin
      for I in P'Range loop
         pragma Loop_Invariant (for all II in P'First .. I - 1 => R (II) = P (II));
         R (I) := P (I);
      end loop;
      return R;
   end To_M;

   --  SPoly (Ntt) -> Rnd.Poly; same Fq component, different array type.
   function To_R (P : SPoly) return Rnd.Poly
     with Global => null,
          Post => (for all I in Rnd.Poly'Range => To_R'Result (I) = P (I))
   is
      R : Rnd.Poly := (others => 0);
   begin
      for I in P'Range loop
         pragma Loop_Invariant (for all II in P'First .. I - 1 => R (II) = P (II));
         R (I) := P (I);
      end loop;
      return R;
   end To_R;

   function Add_Poly (A, B : SPoly) return SPoly
     with Global => null
   is
      R : SPoly := (others => 0);
   begin
      for I in A'Range loop
         R (I) := Fld.Add (A (I), B (I));
      end loop;
      return R;
   end Add_Poly;

   function Sub_Poly (A, B : SPoly) return SPoly
     with Global => null
   is
      R : SPoly := (others => 0);
   begin
      for I in A'Range loop
         R (I) := Fld.Sub (A (I), B (I));
      end loop;
      return R;
   end Sub_Poly;

   --  Matrix row r times a length-l hat vector, accumulated, then INTT.
   function Mat_Vec_Row
     (A_Hat : Smp.Matrix; Row : Natural; V_Hat : L_Vec) return SPoly
     with Global => null, Pre => Row <= K_Dim - 1
   is
      Acc : SPoly := (others => 0);
   begin
      for S in 0 .. L_Dim - 1 loop
         Acc := Add_Poly (Acc, Ntt.Pointwise (A_Hat (Row, S), V_Hat (S)));
      end loop;
      Ntt.Inv_NTT (Acc);
      return Acc;
   end Mat_Vec_Row;

   ---------------------------------------------------------------------------
   --  RejBoundedPoly (Alg.31 with CoeffFromHalfByte Alg.15, eta = 4):
   --  squeeze SHAKE256(seed||nonce_le16), accept nibble b<9 as coeff 4-b.
   ---------------------------------------------------------------------------
   function Rej_Bounded_Poly (Seed : Byte_Array; Nonce : Natural) return SPoly
     with Global => null,
          Pre => Seed'Length = 64 and then Nonce <= 65535
   is
      In_Buf : Byte_Array (0 .. 65) := (others => 0);
      Buf    : Byte_Array (0 .. 1023);
      R      : SPoly := (others => 0);
      Count  : Natural := 0;
   begin
      for I in 0 .. 63 loop
         In_Buf (I) := Seed (Seed'First + I);
      end loop;
      In_Buf (64) := Byte (Nonce mod 256);
      In_Buf (65) := Byte (Nonce / 256);
      Shake256 (In_Buf, Buf);

      for I in Buf'Range loop
         pragma Loop_Invariant (Count <= 256);
         exit when Count = 256;
         declare
            B  : constant Natural := Natural (Buf (I));
            Z0 : constant Natural := B mod 16;
            Z1 : constant Natural := B / 16;
         begin
            if Z0 < 9 and then Count < 256 then
               R (Count) := Canon (4 - Integer_32 (Z0));
               Count := Count + 1;
            end if;
            if Z1 < 9 and then Count < 256 then
               R (Count) := Canon (4 - Integer_32 (Z1));
               Count := Count + 1;
            end if;
         end;
      end loop;
      return R;
   end Rej_Bounded_Poly;

   ---------------------------------------------------------------------------
   --  ExpandMask one polynomial (Alg.34): y = BitUnpack(SHAKE256(seed||nonce),
   --  gamma1-1, gamma1). Reuses the proven 20-bit Simple_Bit_Unpack, then maps
   --  raw -> centered (gamma1 - raw) -> canonical, exactly as Sig_Decode does.
   ---------------------------------------------------------------------------
   function Expand_Mask_Poly (Seed : Byte_Array; Nonce : Natural) return SPoly
     with Global => null,
          Pre => Seed'Length = 64 and then Nonce <= 65535
   is
      In_Buf : Byte_Array (0 .. 65) := (others => 0);
      Buf    : Byte_Array (0 .. 639);     --  32 * 20 bits
      R      : SPoly := (others => 0);
   begin
      for I in 0 .. 63 loop
         In_Buf (I) := Seed (Seed'First + I);
      end loop;
      In_Buf (64) := Byte (Nonce mod 256);
      In_Buf (65) := Byte (Nonce / 256);
      Shake256 (In_Buf, Buf);

      declare
         Raw : constant Poly := Cod.Simple_Bit_Unpack (Buf, 20, 1_048_575);
      begin
         for I in R'Range loop
            --  Raw(I) in 0..2^20-1; C in -(gamma1-1)..gamma1.
            R (I) := Canon (Gamma1 - Raw (I));
         end loop;
      end;
      return R;
   end Expand_Mask_Poly;

   --  MakeHint bit (Alg.39): 1 iff high bits differ.
   function Make_Hint_Bit (A_Coeff, B_Coeff : Fq) return Cod.Hint_Bit
     with Global => null
   is
   begin
      return (if Rnd.High_Bits (A_Coeff) /= Rnd.High_Bits (B_Coeff)
              then 1 else 0);
   end Make_Hint_Bit;

   ---------------------------------------------------------------------------
   --  Key_Gen (Algorithm 6)
   ---------------------------------------------------------------------------
   procedure Key_Gen
     (Seed : Byte_Array;
      PK   : out Public_Key;
      SK   : out Secret_Key)
   is
      A_Hat   : Smp.Matrix;
      S1_Hat  : L_Vec := (others => (others => 0));
      Rho     : Byte_Array (0 .. 31) := (others => 0);
      Rho_P   : Byte_Array (0 .. 63) := (others => 0);
      KK      : Byte_Array (0 .. 31) := (others => 0);
      T1_All  : Cod.T1_Vec := (others => (others => 0));
   begin
      SK := (Rho => (others => 0), KK => (others => 0), Tr => (others => 0),
             S1 => (others => (others => 0)), S2 => (others => (others => 0)),
             T0 => (others => (others => 0)));

      --  (rho, rho', K) = H(seed || k || l, 128)
      declare
         In_Buf : Byte_Array (0 .. 33) := (others => 0);
         Out128 : Byte_Array (0 .. 127);
      begin
         for I in 0 .. 31 loop
            In_Buf (I) := Seed (Seed'First + I);
         end loop;
         In_Buf (32) := Byte (K_Dim);
         In_Buf (33) := Byte (L_Dim);
         Shake256 (In_Buf, Out128);
         for I in 0 .. 31 loop Rho (I)   := Out128 (I);        end loop;
         for I in 0 .. 63 loop Rho_P (I) := Out128 (32 + I);   end loop;
         for I in 0 .. 31 loop KK (I)    := Out128 (96 + I);   end loop;
      end;

      Smp.Expand_A (Rho, A_Hat);

      --  s1 (l polys), s2 (k polys) from rho'
      for S in 0 .. L_Dim - 1 loop
         SK.S1 (S) := Rej_Bounded_Poly (Rho_P, S);
      end loop;
      for R in 0 .. K_Dim - 1 loop
         SK.S2 (R) := Rej_Bounded_Poly (Rho_P, L_Dim + R);
      end loop;

      --  s1_hat = NTT(s1)
      for S in 0 .. L_Dim - 1 loop
         declare
            P : SPoly := SK.S1 (S);
         begin
            Ntt.NTT (P);
            S1_Hat (S) := P;
         end;
      end loop;

      --  t = INTT(A o s1_hat) + s2 ; (t1, t0) = Power2Round(t)
      for R in 0 .. K_Dim - 1 loop
         pragma Loop_Invariant
           (for all RR in 0 .. R - 1 =>
              (for all J in Poly'Range => T1_All (RR) (J) in 0 .. 1023));
         declare
            T_Poly : constant SPoly :=
              Add_Poly (Mat_Vec_Row (A_Hat, R, S1_Hat), SK.S2 (R));
            T1r : Poly := (others => 0);
         begin
            for I in 0 .. 255 loop
               pragma Loop_Invariant
                 (for all JJ in 0 .. I - 1 => T1r (JJ) in 0 .. 1023);
               declare
                  R1 : Rnd.P2R_High;
                  R0 : Rnd.P2R_Low;
               begin
                  Rnd.Power2Round (T_Poly (I), R1, R0);
                  T1r (I)       := Coeff (R1);                 --  0 .. 1023
                  SK.T0 (R) (I) := Canon (Integer_32 (R0));    --  centered
               end;
            end loop;
            T1_All (R) := T1r;
         end;
      end loop;

      PK     := Cod.Pk_Encode (Rho, T1_All);
      SK.Rho := Rho;
      SK.KK  := KK;
      Shake256 (Byte_Array (PK), SK.Tr);
   end Key_Gen;

   ---------------------------------------------------------------------------
   --  Sign (Algorithm 7), deterministic variant (rnd = 0).
   ---------------------------------------------------------------------------
   procedure Sign
     (SK      : Secret_Key;
      Message : Byte_Array;
      Context : Byte_Array;
      Sig     : out Signature;
      Ok      : out Boolean)
   is
      A_Hat  : Smp.Matrix;
      S1_Hat : L_Vec := (others => (others => 0));
      S2_Hat : K_Vec := (others => (others => 0));
      T0_Hat : K_Vec := (others => (others => 0));

      Mu      : Byte_Array (0 .. 63) := (others => 0);
      Rho_Pp  : Byte_Array (0 .. 63) := (others => 0);  --  rho''
   begin
      Sig := (others => 0);
      Ok  := False;

      Smp.Expand_A (SK.Rho, A_Hat);

      for S in 0 .. L_Dim - 1 loop
         declare P : SPoly := SK.S1 (S); begin Ntt.NTT (P); S1_Hat (S) := P; end;
      end loop;
      for R in 0 .. K_Dim - 1 loop
         declare P : SPoly := SK.S2 (R); begin Ntt.NTT (P); S2_Hat (R) := P; end;
      end loop;
      for R in 0 .. K_Dim - 1 loop
         declare P : SPoly := SK.T0 (R); begin Ntt.NTT (P); T0_Hat (R) := P; end;
      end loop;

      --  M' = 0x00 || len(ctx) || ctx || msg ; mu = H(tr || M', 64)
      declare
         M_Prime : Byte_Array (0 .. Message'Length + Context'Length + 1) :=
           (others => 0);
         Tr_Mp   : Byte_Array (0 .. 64 + (Message'Length + Context'Length + 2)
                                 - 1) := (others => 0);
      begin
         M_Prime (0) := 0;
         M_Prime (1) := Byte (Context'Length);
         for I in 0 .. Context'Length - 1 loop
            M_Prime (2 + I) := Context (Context'First + I);
         end loop;
         for I in 0 .. Message'Length - 1 loop
            M_Prime (2 + Context'Length + I) := Message (Message'First + I);
         end loop;

         for I in 0 .. 63 loop Tr_Mp (I) := SK.Tr (I); end loop;
         for I in M_Prime'Range loop Tr_Mp (64 + I) := M_Prime (I); end loop;
         Shake256 (Tr_Mp, Mu);
      end;

      --  rho'' = H(K || rnd(32 zeros) || mu, 64)
      declare
         Buf : Byte_Array (0 .. 127) := (others => 0);
      begin
         for I in 0 .. 31 loop Buf (I) := SK.KK (I); end loop;
         --  Buf(32..63) = rnd = 0 (deterministic)
         for I in 0 .. 63 loop Buf (64 + I) := Mu (I); end loop;
         Shake256 (Buf, Rho_Pp);
      end;

      --  ---- rejection loop ----
      for Attempt in 0 .. Max_Attempts - 1 loop
         declare
            Kappa  : constant Natural := Attempt * L_Dim;
            Y      : L_Vec := (others => (others => 0));
            Y_Hat  : L_Vec := (others => (others => 0));
            W      : K_Vec := (others => (others => 0));
            W1     : K_Vec := (others => (others => 0));
            W1B    : Byte_Array (0 .. K_Dim * 128 - 1) := (others => 0);
            C_Tld  : Byte_Array (0 .. C_Tilde_Bytes - 1) := (others => 0);
            C_Poly : SPoly := (others => 0);
            C_Hat  : SPoly := (others => 0);
            Z      : L_Vec := (others => (others => 0));
            A_Vec  : K_Vec := (others => (others => 0));   --  w - c*s2
            R0_Vec : K_Vec := (others => (others => 0));   --  LowBits(w - c*s2)
            Ct0    : K_Vec := (others => (others => 0));
            Reject : Boolean := False;
         begin
            --  y = ExpandMask(rho'', kappa) ; w = INTT(A o NTT(y))
            for S in 0 .. L_Dim - 1 loop
               Y (S) := Expand_Mask_Poly (Rho_Pp, Kappa + S);
            end loop;
            for S in 0 .. L_Dim - 1 loop
               declare P : SPoly := Y (S); begin Ntt.NTT (P); Y_Hat (S) := P; end;
            end loop;
            for R in 0 .. K_Dim - 1 loop
               W (R) := Mat_Vec_Row (A_Hat, R, Y_Hat);
            end loop;

            --  w1 = HighBits(w) ; w1bytes = W1Encode(w1)
            for R in 0 .. K_Dim - 1 loop
               pragma Loop_Invariant
                 (for all RR in 0 .. R - 1 =>
                    (for all J in SPoly'Range => W1 (RR) (J) <= Rnd.M_Bins - 1));
               for I in SPoly'Range loop
                  pragma Loop_Invariant
                    (for all JJ in 0 .. I - 1 => W1 (R) (JJ) <= Rnd.M_Bins - 1);
                  W1 (R) (I) := Rnd.High_Bits (W (R) (I));
               end loop;
            end loop;
            for R in 0 .. K_Dim - 1 loop
               declare
                  Enc : constant Rnd.W1_Bytes := Rnd.W1_Encode (To_R (W1 (R)));
               begin
                  for I in Enc'Range loop
                     W1B (R * 128 + I) := Enc (I);
                  end loop;
               end;
            end loop;

            --  c_tilde = H(mu || w1bytes, 48)
            declare
               Mu_W1 : Byte_Array (0 .. 64 + W1B'Length - 1) := (others => 0);
            begin
               for I in 0 .. 63 loop Mu_W1 (I) := Mu (I); end loop;
               for I in W1B'Range loop Mu_W1 (64 + I) := W1B (I); end loop;
               Shake256 (Mu_W1, C_Tld);
            end;

            --  c = SampleInBall(c_tilde) ; c_hat = NTT(c)
            Smp.Sample_In_Ball (C_Tld, C_Poly);
            C_Hat := C_Poly;
            Ntt.NTT (C_Hat);

            --  z = y + INTT(c_hat o s1_hat)
            for S in 0 .. L_Dim - 1 loop
               declare
                  Cs1 : SPoly := Ntt.Pointwise (C_Hat, S1_Hat (S));
               begin
                  Ntt.Inv_NTT (Cs1);
                  Z (S) := Add_Poly (Y (S), Cs1);
               end;
            end loop;

            --  A_vec = w - INTT(c_hat o s2_hat) ; r0 = LowBits(A_vec)
            for R in 0 .. K_Dim - 1 loop
               declare
                  Cs2 : SPoly := Ntt.Pointwise (C_Hat, S2_Hat (R));
               begin
                  Ntt.Inv_NTT (Cs2);
                  A_Vec (R) := Sub_Poly (W (R), Cs2);
               end;
               for I in SPoly'Range loop
                  R0_Vec (R) (I) := Canon (Rnd.Low_Bits (A_Vec (R) (I)));
               end loop;
            end loop;

            --  reject if ||z||inf >= gamma1-beta or ||r0||inf >= gamma2-beta
            for S in 0 .. L_Dim - 1 loop
               if not Rnd.Inf_Norm_OK (To_R (Z (S)), Gamma1 - Beta) then
                  Reject := True;
               end if;
            end loop;
            for R in 0 .. K_Dim - 1 loop
               if not Rnd.Inf_Norm_OK (To_R (R0_Vec (R)), Gamma2 - Beta) then
                  Reject := True;
               end if;
            end loop;

            if not Reject then
               --  ct0 = INTT(c_hat o t0_hat) ; B = A_vec + ct0
               for R in 0 .. K_Dim - 1 loop
                  declare
                     P : SPoly := Ntt.Pointwise (C_Hat, T0_Hat (R));
                  begin
                     Ntt.Inv_NTT (P);
                     Ct0 (R) := P;
                  end;
               end loop;

               --  reject if ||ct0||inf >= gamma2
               for R in 0 .. K_Dim - 1 loop
                  if not Rnd.Inf_Norm_OK (To_R (Ct0 (R)), Gamma2) then
                     Reject := True;
                  end if;
               end loop;

               if not Reject then
                  declare
                     H_Bits : Cod.H_Vec := (others => (others => 0));
                     Weight : Natural := 0;
                  begin
                     for R in 0 .. K_Dim - 1 loop
                        pragma Loop_Invariant (Weight <= R * N);
                        for I in SPoly'Range loop
                           pragma Loop_Invariant (Weight <= R * N + I);
                           declare
                              B_Co : constant Fq :=
                                Fld.Add (A_Vec (R) (I), Ct0 (R) (I));
                              Hb : constant Cod.Hint_Bit :=
                                Make_Hint_Bit (A_Vec (R) (I), B_Co);
                           begin
                              H_Bits (R) (I) := Hb;
                              Weight := Weight + Natural (Hb);
                           end;
                        end loop;
                     end loop;

                     if Weight <= Omega then
                        --  accept: assemble the signature.
                        declare
                           Zc : Cod.Z_Vec := (others => (others => 0));
                           Ct : Cod.C_Tilde_Array;
                        begin
                           for S in 0 .. L_Dim - 1 loop
                              Zc (S) := To_M (Z (S));
                           end loop;
                           for I in Ct'Range loop Ct (I) := C_Tld (I); end loop;
                           Sig := Cod.Sig_Encode (Ct, Zc, H_Bits);
                           Ok  := True;
                           return;
                        end;
                     end if;
                  end;
               end if;
            end if;
         end;
      end loop;
      --  Loop exhausted (unreachable in practice): fail-closed.
      Sig := (others => 0);
      Ok  := False;
   end Sign;

end LTHING_MLDSA_Sign;
