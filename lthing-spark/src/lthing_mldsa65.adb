------------------------------------------------------------------------------
--  LTHING.MLDSA65 (body) — FIPS 204 ML-DSA-65 verifier (Alg. 3 + Alg. 8).
--
--  Replaces the historical fail-closed stub with the real verifier. The flow
--  follows FIPS 204:
--    * Alg. 3 (ML-DSA.Verify, external/pure): build M' = 0x00 || len(ctx) ||
--      ctx || msg, then call Verify_internal.
--    * Alg. 8 (ML-DSA.Verify_internal): decode pk/sig, expand A, recompute
--      w1 = UseHint(h, A z - c t1 2^d), and accept iff
--          ||z||_inf < gamma1 - beta
--      AND c_tilde2 = c_tilde AND popcount(h) <= omega.
--
--  SPARK posture: SPARK_Mode (On). Proof target is AoRTE + flow. It composes
--  the NTT / sampling / codec / round layers, all now SPARK_Mode (On) and
--  proved free of run-time errors; the field layer it leans on is proved with
--  range postconditions. Functional (cryptographic) correctness stays gated by
--  the 15-vector FIPS 204 sigVer KAT (test_kat.adb).
--
--  Fail-closed is preserved: any decode failure, malformed hint, norm overflow,
--  challenge mismatch, or excess hint weight returns False. Verify only returns
--  True on a genuine FIPS 204 acceptance.
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

package body LTHING_MLDSA65 is

   package Fld renames LTHING_MLDSA_Field;
   package Ntt renames LTHING_MLDSA_NTT;
   package Cod renames LTHING_MLDSA_Codec;
   package Rnd renames LTHING_MLDSA_Round;
   package Smp renames LTHING_MLDSA_Sample;

   subtype FPoly is Ntt.Poly;            --  array (0..255) of Fq

   Two_Pow_D : constant := 8_192;        --  2^d, d = 13

   --  Coeff-wise add over Fq.
   function Add_Poly (A, B : FPoly) return FPoly
     with Global => null
   is
      R : FPoly;
   begin
      for I in FPoly'Range loop
         R (I) := Fld.Add (A (I), B (I));
      end loop;
      return R;
   end Add_Poly;

   --  Coeff-wise sub over Fq.
   function Sub_Poly (A, B : FPoly) return FPoly
     with Global => null
   is
      R : FPoly;
   begin
      for I in FPoly'Range loop
         R (I) := Fld.Sub (A (I), B (I));
      end loop;
      return R;
   end Sub_Poly;

   ---------------------------------------------------------------------------
   --  Verify — FIPS 204 Algorithm 3 + Algorithm 8.
   ---------------------------------------------------------------------------
   function Verify
     (PK      : Public_Key;
      Message : Byte_Array;
      Context : Byte_Array;
      Sig     : Signature) return Boolean
   is
      --  --- Alg. 3: build M' = 0x00 || len(ctx) || ctx || msg ---
      M_Prime : Byte_Array (0 .. Message'Length + Context'Length + 1) :=
        (others => 0);

      --  --- decode outputs ---
      Rho     : Cod.Rho_Array;
      T1      : Cod.T1_Vec;
      C_Tilde : Cod.C_Tilde_Array;
      Z       : Cod.Z_Vec;
      H       : Cod.H_Vec;
      Ok      : Boolean;

      A_Hat   : Smp.Matrix;          --  k x l, NTT domain

      C_Poly  : Ntt.Poly;            --  challenge, coeffs in {-1,0,+1}
      C_Hat   : FPoly;

      Tr       : Byte_Array (0 .. 63);
      Mu       : Byte_Array (0 .. 63);
      C_Tilde2 : Byte_Array (0 .. C_Tilde_Bytes - 1);

      W1_Bytes : Byte_Array (0 .. K_Dim * 128 - 1) := (others => 0);

      Hint_Weight : Natural := 0;
   begin
      --  ---- Alg. 3 prefix construction ----
      M_Prime (0) := 0;
      M_Prime (1) := Byte (Context'Length);
      for I in 0 .. Context'Length - 1 loop
         M_Prime (2 + I) := Context (Context'First + I);
      end loop;
      for I in 0 .. Message'Length - 1 loop
         M_Prime (2 + Context'Length + I) := Message (Message'First + I);
      end loop;

      --  ---- Alg. 8 step 1: pkDecode ----
      Cod.Pk_Decode (PK, Rho, T1);

      --  ---- step 2: sigDecode (fail-closed) ----
      Cod.Sig_Decode (Sig, C_Tilde, Z, H, Ok);
      if not Ok then
         return False;
      end if;

      --  ---- step 3: A_hat := ExpandA(rho) (NTT domain) ----
      declare
         Rho_BA : Byte_Array (0 .. 31);
      begin
         for I in Rho'Range loop
            Rho_BA (I) := Rho (I);
         end loop;
         Smp.Expand_A (Rho_BA, A_Hat);
      end;

      --  ---- step 4: tr := H(pk, 64); mu := H(tr || M', 64) ----
      Sponge (Input  => Byte_Array (PK),
              Rate   => Rate_SHAKE256,
              Domain => Domain_SHAKE,
              Output => Tr);

      declare
         Tr_Mp : Byte_Array (0 .. 64 + M_Prime'Length - 1) := (others => 0);
      begin
         for I in 0 .. 63 loop
            Tr_Mp (I) := Tr (I);
         end loop;
         for I in M_Prime'Range loop
            Tr_Mp (64 + I) := M_Prime (I);
         end loop;
         Sponge (Input  => Tr_Mp,
                 Rate   => Rate_SHAKE256,
                 Domain => Domain_SHAKE,
                 Output => Mu);
      end;

      --  ---- step 5: c := SampleInBall(c_tilde); c_hat := NTT(c) ----
      declare
         Ct_BA : Byte_Array (0 .. C_Tilde_Bytes - 1);
      begin
         for I in C_Tilde'Range loop
            Ct_BA (I) := C_Tilde (I);
         end loop;
         Smp.Sample_In_Ball (Ct_BA, C_Poly);
      end;
      --  Sample_In_Ball already emits canonical Fq (-1 stored as Q-1), so the
      --  sign->Fq mapping is already applied; copy then NTT (in place).
      C_Hat := C_Poly;
      Ntt.NTT (C_Hat);

      --  ---- steps 6-8: per-row w(r), w1(r) = UseHint(h(r), w(r)), encode ----
      declare
         Z_Hat : array (0 .. L_Dim - 1) of FPoly := (others => (others => 0));
      begin
         --  Pre-transform z(s) once.
         for S in 0 .. L_Dim - 1 loop
            for I in FPoly'Range loop
               Z_Hat (S) (I) := Z (S) (I);    --  already canonical 0..Q-1
            end loop;
            Ntt.NTT (Z_Hat (S));
         end loop;

         for R in 0 .. K_Dim - 1 loop
            declare
               Acc     : FPoly := (others => 0);
               T1d     : FPoly;
               T1d_Hat : FPoly;
               W_Hat   : FPoly;
               W_Poly  : FPoly;
               W1_R    : Rnd.Poly := (others => 0);
            begin
               --  w_hat(r) = sum_s A_hat(r,s) o NTT(z(s)) - c_hat o NTT(t1d(r))
               for S in 0 .. L_Dim - 1 loop
                  Acc := Add_Poly (Acc, Ntt.Pointwise (A_Hat (R, S), Z_Hat (S)));
               end loop;

               --  t1d = t1(r) scaled by 2^d, reduced mod q
               for I in FPoly'Range loop
                  T1d (I) := Fld.Fq
                    ((Integer_64 (T1 (R) (I)) * Two_Pow_D) mod Q);
               end loop;
               T1d_Hat := T1d;
               Ntt.NTT (T1d_Hat);

               W_Hat  := Sub_Poly (Acc, Ntt.Pointwise (C_Hat, T1d_Hat));
               W_Poly := W_Hat;
               Ntt.Inv_NTT (W_Poly);

               --  step 7: w1(r) = UseHint(h(r), w(r)); each result in 0..15.
               for I in FPoly'Range loop
                  pragma Loop_Invariant
                    (for all II in FPoly'First .. I - 1 =>
                       W1_R (II) <= Rnd.M_Bins - 1);
                  W1_R (I) := Rnd.Use_Hint (H (R) (I), W_Poly (I));
               end loop;

               --  step 8: encode this poly's 128 bytes into the right slice.
               declare
                  Enc : constant Rnd.W1_Bytes := Rnd.W1_Encode (W1_R);
               begin
                  for I in Enc'Range loop
                     W1_Bytes (R * 128 + I) := Enc (I);
                  end loop;
               end;
            end;
         end loop;
      end;

      --  c_tilde2 := H(mu || w1bytes, 48)
      declare
         Mu_W1 : Byte_Array (0 .. 64 + W1_Bytes'Length - 1) := (others => 0);
      begin
         for I in 0 .. 63 loop
            Mu_W1 (I) := Mu (I);
         end loop;
         for I in W1_Bytes'Range loop
            Mu_W1 (64 + I) := W1_Bytes (I);
         end loop;
         Sponge (Input  => Mu_W1,
                 Rate   => Rate_SHAKE256,
                 Domain => Domain_SHAKE,
                 Output => C_Tilde2);
      end;

      --  ---- step 9: three acceptance conditions ----

      --  (a) ||z||_inf < gamma1 - beta, checked per poly via Inf_Norm_OK.
      for S in 0 .. L_Dim - 1 loop
         declare
            Zp : Rnd.Poly;
         begin
            for I in FPoly'Range loop
               Zp (I) := Z (S) (I);
            end loop;
            if not Rnd.Inf_Norm_OK (Zp, Gamma1 - Beta) then
               return False;
            end if;
         end;
      end loop;

      --  (b) hint weight <= omega
      for R in 0 .. K_Dim - 1 loop
         pragma Loop_Invariant (Hint_Weight <= R * 256);
         for I in Cod.Hint_Poly'Range loop
            pragma Loop_Invariant (Hint_Weight <= R * 256 + I);
            Hint_Weight := Hint_Weight + Natural (H (R) (I));
         end loop;
      end loop;
      if Hint_Weight > Omega then
         return False;
      end if;

      --  (c) c_tilde2 = c_tilde
      for I in C_Tilde'Range loop
         if C_Tilde2 (I) /= C_Tilde (I) then
            return False;
         end if;
      end loop;

      return True;
   end Verify;

end LTHING_MLDSA65;
