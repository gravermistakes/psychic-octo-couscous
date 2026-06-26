------------------------------------------------------------------------------
--  LTHING.MLDSA87.Codec body — FIPS 204 decoding, SPARK_Mode (On).
--
--  Mirror of LTHING_MLDSA_Codec sized to ML-DSA-87: k=8, l=7, omega=75,
--  c_tilde=64B, Sig_Bytes=4627, PK_Bytes=2592.  Only the decode path is
--  present (Get_Bit, Simple_Bit_Unpack, Pk_Decode, Sig_Decode) since the
--  Level-5 package has no signer.
--
--  Every routine is proved free of run-time errors (AoRTE); exact values
--  are validated by the FIPS 204 ML-DSA-87 sigVer KAT (test_kat87).
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_MLDSA87_Codec is

   --  ML-DSA-87: gamma1 = 2**19, so z fields are 20 bits each (same as -65).
   Z_Bit_Len : constant := 20;
   Z_Bytes   : constant := (N * Z_Bit_Len) / 8;   --  640 per polynomial
   T1_Bytes  : constant := (N * 10) / 8;          --  320 per polynomial

   --  Hint encoding layout: last Omega + K_Dim = 75 + 8 = 83 bytes of Sig.
   Hint_Off  : constant := Sig_Bytes - (Omega + K_Dim);   --  4544

   ----------------------------------------------------------------------------
   --  Get_Bit (FIPS 204 bit indexing within a byte slice)
   ----------------------------------------------------------------------------
   function Get_Bit (V : Byte_Array; N : Natural) return Coeff is
      B       : constant Byte := V (V'First + N / 8);
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
            R (I) := Acc;
         end;
      end loop;
      return R;
   end Simple_Bit_Unpack;

   ----------------------------------------------------------------------------
   --  Pk_Decode (Algorithm 23)
   --    rho = pk(0..31); t1(i) = SimpleBitUnpack(pk(32+320i .. +319), 10)
   --  k = K_Dim = 8 for ML-DSA-87.
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
            T1 (I) := Simple_Bit_Unpack (Slice, 10, 1023);
         end;
      end loop;
   end Pk_Decode;

   ----------------------------------------------------------------------------
   --  Sig_Decode (Algorithm 27) + HintBitUnpack (Algorithm 21)
   --  c_tilde = sig(0..63); z(i) = BitUnpack(sig(64+640i..+639), ...);
   --  hint in last 83 bytes (Hint_Off = 4544).
   ----------------------------------------------------------------------------
   procedure Sig_Decode
     (Sig     : Signature;
      C_Tilde : out C_Tilde_Array;
      Z       : out Z_Vec;
      H       : out H_Vec;
      Ok      : out Boolean)
   is
   begin
      --  c_tilde = sig(0 .. 63)
      for I in C_Tilde_Array'Range loop
         C_Tilde (I) := Sig (I);
      end loop;

      --  z(i) = BitUnpack(sig(64 + 640i .. +639), gamma1-1, gamma1), bitlen 20.
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
                  C : constant Coeff := Gamma1 - Raw (J);
               begin
                  if C < 0 then
                     Z (I) (J) := C + Q;
                  else
                     Z (I) (J) := C;
                  end if;
               end;
            end loop;
         end;
      end loop;

      --  HintBitUnpack (Algorithm 21): last Omega + K_Dim = 83 bytes.
      H  := (others => (others => 0));
      Ok := True;

      declare
         Index : Natural := 0;
         Prev  : Natural := 0;
      begin
         Polys :
         for I in H_Vec'Range loop
            pragma Loop_Invariant (Index <= Omega);

            declare
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

end LTHING_MLDSA87_Codec;
