------------------------------------------------------------------------------
--  LTHING.MLDSA.Codec — body. FIPS 204 decoding primitives, SPARK_Mode (On).
--
--  Each routine is proved free of run-time errors and bounds its outputs into
--  the ranges stated in the spec. The hint decoder (Algorithm 21) is the only
--  routine that can report failure (Ok=False) and does so on any malformed
--  encoding: this is fail-closed by construction.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_MLDSA_Codec is

   --  Gamma1 = 2**19 = 524288 for ML-DSA-65. BitUnpack on z uses (a,b) =
   --  (Gamma1-1, Gamma1), so bitlen = bitlen(a+b) = bitlen(2*Gamma1-1) = 20.
   Z_Bit_Len : constant := 20;
   Z_Bytes   : constant := (N * Z_Bit_Len) / 8;   --  640 per polynomial
   T1_Bytes  : constant := (N * 10) / 8;          --  320 per polynomial

   --  Hint encoding layout inside the signature (Algorithm 27): the hint blob
   --  is the last Omega + K_Dim = 61 bytes, beginning at this offset.
   Hint_Off  : constant := Sig_Bytes - (Omega + K_Dim);   --  3248

   ----------------------------------------------------------------------------
   --  Get_Bit (FIPS 204 bit indexing within a byte slice)
   ----------------------------------------------------------------------------
   function Get_Bit (V : Byte_Array; N : Natural) return Coeff is
      B : constant Byte := V (V'First + N / 8);
      Shifted : constant Byte := Shift_Right (B, N mod 8);
   begin
      return Coeff (Shifted and 1);
   end Get_Bit;

   ----------------------------------------------------------------------------
   --  Simple_Bit_Unpack (Algorithm 19)
   --    coeff(i) = sum_{j=0..bitlen-1} bit(i*bitlen + j) * 2**j
   ----------------------------------------------------------------------------
   function Simple_Bit_Unpack
     (V : Byte_Array; Bit_Len : Positive; Hi : Coeff) return Poly
   is
      R : Poly := (others => 0);
   begin
      for I in Poly'Range loop
         pragma Loop_Invariant (for all II in 0 .. I - 1 => R (II) in 0 .. Hi);

         declare
            --  Weight is the place value 2**J of the bit currently being added
            --  and Acc the partial sum. Both are bounded by the concrete value
            --  Hi (+1), so every check is linear and stays inside Integer_32.
            --
            --  Two guards keep the proof linear without any 2**Bit_Len term:
            --    * the place value Weight is doubled only while 2*Weight <= Hi+1
            --      (so Weight <= Hi+1 always);
            --    * the bit contribution is added only when it keeps Acc <= Hi.
            --  Because Hi = 2**Bit_Len - 1 and J ranges 0 .. Bit_Len-1, the true
            --  place values are all <= (Hi+1)/2 and every genuine contribution
            --  fits, so neither guard ever blocks for in-spec input and the
            --  LSB-first value sum(bit_j * 2**j) is reproduced exactly. The
            --  guards exist purely to make the 0..Hi range bound provable; the
            --  exact decoded values are checked by the FIPS 204 KAT at run time.
            Acc    : Coeff := 0;
            Weight : Coeff := 1;
         begin
            for J in 0 .. Bit_Len - 1 loop
               pragma Loop_Invariant (Weight >= 1);
               pragma Loop_Invariant (Weight <= Hi + 1);
               pragma Loop_Invariant (Acc >= 0);
               pragma Loop_Invariant (Acc <= Hi);

               declare
                  Contrib : constant Coeff :=
                    Get_Bit (V, I * Bit_Len + J) * Weight;
               begin
                  if Acc <= Hi - Contrib then
                     Acc := Acc + Contrib;
                  end if;
               end;

               if 2 * Weight <= Hi + 1 then
                  Weight := Weight * 2;
               end if;
            end loop;
            --  On loop exit the invariant Acc <= Hi carries to the result.
            R (I) := Acc;
         end;
      end loop;
      return R;
   end Simple_Bit_Unpack;

   ----------------------------------------------------------------------------
   --  Pk_Decode (Algorithm 23)
   --    rho = pk(0..31); t1(i) = SimpleBitUnpack(pk(32+320i .. +319), 10)
   ----------------------------------------------------------------------------
   procedure Pk_Decode
     (PK  : Public_Key;
      Rho : out Rho_Array;
      T1  : out T1_Vec)
   is
   begin
      for I in Rho_Array'Range loop
         Rho (I) := PK (I);
      end loop;

      T1 := (others => (others => 0));

      for I in T1_Vec'Range loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in Poly'Range => T1 (II) (J) in 0 .. 1023));

         declare
            Base  : constant Natural := 32 + T1_Bytes * I;
            Slice : constant Byte_Array := PK (Base .. Base + T1_Bytes - 1);
         begin
            --  2**10 - 1 = 1023, so the helper's postcondition gives the bound.
            T1 (I) := Simple_Bit_Unpack (Slice, 10, 1023);
         end;
      end loop;
   end Pk_Decode;

   ----------------------------------------------------------------------------
   --  Sig_Decode (Algorithm 27) + HintBitUnpack (Algorithm 21)
   ----------------------------------------------------------------------------
   procedure Sig_Decode
     (Sig     : Signature;
      C_Tilde : out C_Tilde_Array;
      Z       : out Z_Vec;
      H       : out H_Vec;
      Ok      : out Boolean)
   is
   begin
      --  c_tilde = sig(0 .. 47)
      for I in C_Tilde_Array'Range loop
         C_Tilde (I) := Sig (I);
      end loop;

      --  z(i) = BitUnpack(sig(48 + 640i .. +639), gamma1-1, gamma1), bitlen 20.
      Z := (others => (others => 0));
      for I in Z_Vec'Range loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in Poly'Range => Z (II) (J) in 0 .. Q - 1));

         declare
            Base  : constant Natural := C_Tilde_Bytes + Z_Bytes * I;
            Slice : constant Byte_Array := Sig (Base .. Base + Z_Bytes - 1);
            Raw   : constant Poly := Simple_Bit_Unpack (Slice, Z_Bit_Len, 1_048_575);
         begin
            for J in Poly'Range loop
               pragma Loop_Invariant
                 (for all JJ in 0 .. J - 1 => Z (I) (JJ) in 0 .. Q - 1);
               pragma Loop_Invariant
                 (for all II in 0 .. I - 1 =>
                    (for all JJ in Poly'Range => Z (II) (JJ) in 0 .. Q - 1));

               declare
                  --  Raw(J) in 0 .. 2**20-1 = 1048575 (helper postcondition).
                  C : constant Coeff := Gamma1 - Raw (J);
                  --  Centered value in -(gamma1-1) .. gamma1.
               begin
                  if C < 0 then
                     Z (I) (J) := C + Q;     --  C >= -(gamma1-1) > -Q, so > 0
                  else
                     Z (I) (J) := C;         --  C <= gamma1 = 524288 < Q
                  end if;
               end;
            end loop;
         end;
      end loop;

      --  HintBitUnpack (Algorithm 21) over the last Omega+K_Dim bytes.
      H  := (others => (others => 0));
      Ok := True;

      declare
         Index : Natural := 0;   --  running cursor into the Omega index bytes
         Prev  : Natural := 0;   --  previous position within current polynomial
      begin
         Polys :
         for I in H_Vec'Range loop
            pragma Loop_Invariant (Index <= Omega);

            declare
               --  end pointer for polynomial I lives at offset Omega + I.
               Last : constant Natural :=
                 Natural (Sig (Hint_Off + Omega + I));
            begin
               if Last < Index or else Last > Omega then
                  Ok := False;
                  exit Polys;
               end if;

               for JJ in Index .. Last - 1 loop
                  pragma Loop_Invariant (JJ >= Index);
                  pragma Loop_Invariant (Last <= Omega);

                  declare
                     Pos : constant Natural :=
                       Natural (Sig (Hint_Off + JJ));
                  begin
                     --  positions within a polynomial must strictly increase
                     if JJ > Index and then Pos <= Prev then
                        Ok := False;
                        exit Polys;
                     end if;
                     H (I) (Pos) := 1;
                     Prev := Pos;
                  end;
               end loop;

               Index := Last;
            end;
         end loop Polys;

         --  Trailing padding bytes sig(Hint_Off+Index .. Hint_Off+Omega-1)
         --  must all be zero, else the encoding is malformed.
         if Ok then
            for JJ in Index .. Omega - 1 loop
               if Sig (Hint_Off + JJ) /= 0 then
                  Ok := False;
                  exit;
               end if;
            end loop;
         end if;
      end;
   end Sig_Decode;

end LTHING_MLDSA_Codec;
