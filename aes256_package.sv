/**
 * AES-256 Package
 * 
 * Description:
 *   This package contains all constants, lookup tables (S-boxes), and utility functions
 *   required for AES-256 encryption and decryption operations.
 * 
 * Features:
 *   - Forward S-box (encryption)
 *   - Inverse S-box (decryption)
 *   - Rcon (Round Constants) for key schedule
 *   - Helper functions for AES operations
 *   - Parameter definitions
 */

package aes256_pkg;

  // AES-256 Parameters
  parameter int AES_KEY_SIZE = 256;        // Key size in bits
  parameter int AES_BLOCK_SIZE = 128;      // Block size in bits
  parameter int AES_STATE_BYTES = 16;      // State is 4x4 bytes (16 bytes total)
  parameter int AES_KEY_BYTES = 32;        // 256-bit key = 32 bytes
  parameter int AES_NUM_ROUNDS = 14;       // AES-256 has 14 rounds
  parameter int AES_SCHED_WORDS = 60;      // Total words in key schedule (4*(Nr+1))

  // Type definitions
  typedef logic [7:0] byte_t;              // 8-bit byte
  typedef logic [31:0] word_t;             // 32-bit word
  typedef logic [127:0] block_t;           // 128-bit block
  typedef logic [255:0] key_t;             // 256-bit key
  typedef byte_t state_t [4][4];           // 4x4 state matrix
  typedef word_t sched_t [AES_SCHED_WORDS];// Key schedule array

  /**
   * Forward S-box (Substitution Box)
   * Used during encryption
   * Maps each byte value (0-255) to its substitution value
   */
  const byte_t sbox[256] = '{
    8'h63, 8'h7c, 8'h77, 8'h7b, 8'hf2, 8'h6b, 8'h6f, 8'hc5,
    8'h30, 8'h01, 8'h67, 8'h2b, 8'hfe, 8'hd7, 8'hab, 8'h76,
    8'hca, 8'h82, 8'hc9, 8'h7d, 8'hfa, 8'h59, 8'h47, 8'hf0,
    8'had, 8'hd4, 8'ha2, 8'haf, 8'h9c, 8'ha4, 8'h72, 8'hc0,
    8'hb7, 8'hfd, 8'h93, 8'h26, 8'h36, 8'h3f, 8'hf7, 8'hcc,
    8'h34, 8'ha5, 8'he5, 8'hf1, 8'h71, 8'hd8, 8'h31, 8'h15,
    8'h04, 8'hc7, 8'h23, 8'hc3, 8'h18, 8'h96, 8'h05, 8'h9a,
    8'h07, 8'h12, 8'h80, 8'he2, 8'heb, 8'h27, 8'hb2, 8'h75,
    8'h09, 8'h83, 8'h2c, 8'h1a, 8'h1b, 8'h6e, 8'h5a, 8'ha0,
    8'h52, 8'h3d, 8'h36, 8'h3f, 8'h41, 8'h50, 8'h54, 8'h55,
    8'h57, 8'h5b, 8'h5d, 8'h60, 8'h61, 8'h65, 8'h66, 8'h67,
    8'h69, 8'h6a, 8'h6c, 8'h6d, 8'h6f, 8'h70, 8'h71, 8'h72,
    8'h7a, 8'h78, 8'h7e, 8'h7f, 8'h80, 8'h81, 8'h83, 8'h82,
    8'h92, 8'h93, 8'h94, 8'h95, 8'h97, 8'h99, 8'h9b, 8'h98,
    8'hc1, 8'hc0, 8'hc2, 8'hc3, 8'hc5, 8'hc4, 8'hc6, 8'hc7,
    8'hd9, 8'hd8, 8'hda, 8'hdb, 8'hdd, 8'hdc, 8'hde, 8'hdf,
    8'he9, 8'he8, 8'hea, 8'heb, 8'hed, 8'hec, 8'hee, 8'hef,
    8'hf9, 8'hf8, 8'hfa, 8'hfb, 8'hfd, 8'hfc, 8'hfe, 8'hff,
    8'h00, 8'h0f, 8'h1f, 8'h2f, 8'h3f, 8'h4f, 8'h5f, 8'h6f,
    8'h7f, 8'h8f, 8'h9f, 8'haf, 8'hbf, 8'hcf, 8'hdf, 8'hef,
    8'h10, 8'h11, 8'h12, 8'h13, 8'h14, 8'h15, 8'h16, 8'h17,
    8'h18, 8'h19, 8'h1a, 8'h1b, 8'h1c, 8'h1d, 8'h1e, 8'h1f,
    8'h20, 8'h21, 8'h22, 8'h23, 8'h24, 8'h25, 8'h26, 8'h27,
    8'h28, 8'h29, 8'h2a, 8'h2b, 8'h2c, 8'h2d, 8'h2e, 8'h2f,
    8'h30, 8'h31, 8'h32, 8'h33, 8'h34, 8'h35, 8'h36, 8'h37,
    8'h38, 8'h39, 8'h3a, 8'h3b, 8'h3c, 8'h3d, 8'h3e, 8'h3f,
    8'h40, 8'h41, 8'h42, 8'h43, 8'h44, 8'h45, 8'h46, 8'h47,
    8'h48, 8'h49, 8'h4a, 8'h4b, 8'h4c, 8'h4d, 8'h4e, 8'h4f,
    8'h50, 8'h51, 8'h52, 8'h53, 8'h54, 8'h55, 8'h56, 8'h57,
    8'h58, 8'h59, 8'h5a, 8'h5b, 8'h5c, 8'h5d, 8'h5e, 8'h5f,
    8'h60, 8'h61, 8'h62, 8'h63, 8'h64, 8'h65, 8'h66, 8'h67,
    8'h68, 8'h69, 8'h6a, 8'h6b, 8'h6c, 8'h6d, 8'h6e, 8'h6f
  };

  /**
   * Inverse S-box
   * Used during decryption
   * Maps each byte value to its inverse substitution value
   */
  const byte_t inv_sbox[256] = '{
    8'h52, 8'h09, 8'h6a, 8'hd5, 8'h30, 8'h36, 8'ha5, 8'h38,
    8'hbf, 8'h40, 8'ha3, 8'h9e, 8'h81, 8'hf3, 8'hd7, 8'hfb,
    8'h7c, 8'he3, 8'h39, 8'h82, 8'h9b, 8'h2f, 8'hff, 8'h87,
    8'h34, 8'h8e, 8'h43, 8'h44, 8'hc4, 8'hde, 8'he9, 8'hcb,
    8'h54, 8'h7b, 8'h94, 8'h32, 8'ha6, 8'hc2, 8'h23, 8'h3d,
    8'hee, 8'h4c, 8'h95, 8'h0b, 8'h42, 8'hfa, 8'hc3, 8'h4e,
    8'h08, 8'h2e, 8'ha1, 8'h66, 8'h28, 8'hd9, 8'h24, 8'hb2,
    8'h76, 8'h5b, 8'ha2, 8'h49, 8'h6d, 8'h8b, 8'hd1, 8'h25,
    8'h72, 8'hf8, 8'hf6, 8'h64, 8'h86, 8'h68, 8'h98, 8'h16,
    8'hd4, 8'ha4, 8'h5c, 8'hcc, 8'h5d, 8'h65, 8'hb6, 8'h92,
    8'h6c, 8'h70, 8'h48, 8'h50, 8'hfd, 8'hed, 8'hb9, 8'hda,
    8'h5e, 8'h15, 8'h46, 8'h57, 8'ha7, 8'h8d, 8'h9d, 8'h84,
    8'h90, 8'hd8, 8'hab, 8'h00, 8'h8c, 8'hbc, 8'hd3, 8'h0a,
    8'hf7, 8'he4, 8'h58, 8'h05, 8'hb8, 8'hb3, 8'h45, 8'h06,
    8'hd0, 8'h2c, 8'h1e, 8'h8f, 8'hca, 8'h3f, 8'h0f, 8'h02,
    8'hc1, 8'haf, 8'hbd, 8'h03, 8'h01, 8'h13, 8'h8a, 8'h6b,
    8'h3a, 8'h91, 8'h11, 8'h41, 8'h4f, 8'h67, 8'hcd, 8'hff,
    8'hce, 8'hd9, 8'h24, 8'he5, 8'he6, 8'hc4, 8'hc5, 8'hc6,
    8'hc7, 8'hc8, 8'hc9, 8'hca, 8'h4b, 8'h4c, 8'h4d, 8'h4e,
    8'h4f, 8'h50, 8'h51, 8'h52, 8'h53, 8'h54, 8'h55, 8'h56,
    8'h57, 8'h58, 8'h59, 8'h5a, 8'h5b, 8'h5c, 8'h5d, 8'h5e,
    8'h5f, 8'h60, 8'h61, 8'h62, 8'h63, 8'h64, 8'h65, 8'h66,
    8'h67, 8'h68, 8'h69, 8'h6a, 8'h6b, 8'h6c, 8'h6d, 8'h6e,
    8'h6f, 8'h70, 8'h71, 8'h72, 8'h73, 8'h74, 8'h75, 8'h76,
    8'h77, 8'h78, 8'h79, 8'h7a, 8'h7b, 8'h7c, 8'h7d, 8'h7e,
    8'h7f, 8'h80, 8'h81, 8'h82, 8'h83, 8'h84, 8'h85, 8'h86,
    8'h87, 8'h88, 8'h89, 8'h8a, 8'h8b, 8'h8c, 8'h8d, 8'h8e,
    8'h8f, 8'h90, 8'h91, 8'h92, 8'h93, 8'h94, 8'h95, 8'h96,
    8'h97, 8'h98, 8'h99, 8'h9a, 8'h9b, 8'h9c, 8'h9d, 8'h9e,
    8'h9f, 8'ha0, 8'ha1, 8'ha2, 8'ha3, 8'ha4, 8'ha5, 8'ha6,
    8'ha7, 8'ha8, 8'ha9, 8'haa, 8'hab, 8'hac, 8'had, 8'hae,
    8'haf, 8'hb0, 8'hb1, 8'hb2, 8'hb3, 8'hb4, 8'hb5, 8'hb6
  };

  /**
   * Round Constants (Rcon)
   * Used in the key expansion/schedule
   * These are powers of 2 in GF(2^8)
   */
  const byte_t rcon[11] = '{
    8'h00, 8'h01, 8'h02, 8'h04, 8'h08, 8'h10,
    8'h20, 8'h40, 8'h80, 8'h1b, 8'h36
  };

  /**
   * Multiplication in GF(2^8) by 0x02 (xtime operation)
   * Galois Field multiplication used in MixColumns transformation
   * Input: byte value
   * Output: value multiplied by 0x02 in GF(2^8)
   */
  function byte_t gmul2(byte_t val);
    byte_t msb = val[7];
    byte_t result = {val[6:0], 1'b0};
    if (msb)
      result = result ^ 8'h1b;  // XOR with 0x1b if overflow
    return result;
  endfunction

  /**
   * Multiplication in GF(2^8) by 0x03
   * Implemented as gmul2(val) XOR val
   */
  function byte_t gmul3(byte_t val);
    return gmul2(val) ^ val;
  endfunction

  /**
   * Multiplication in GF(2^8) by 0x09
   * Used in inverse MixColumns
   */
  function byte_t gmul9(byte_t val);
    byte_t val2 = gmul2(val);
    byte_t val4 = gmul2(val2);
    byte_t val8 = gmul2(val4);
    return val8 ^ val;
  endfunction

  /**
   * Multiplication in GF(2^8) by 0x0b
   * Used in inverse MixColumns
   */
  function byte_t gmul11(byte_t val);
    byte_t val2 = gmul2(val);
    byte_t val4 = gmul2(val2);
    byte_t val8 = gmul2(val4);
    return val8 ^ val2 ^ val;
  endfunction

  /**
   * Multiplication in GF(2^8) by 0x0d
   * Used in inverse MixColumns
   */
  function byte_t gmul13(byte_t val);
    byte_t val2 = gmul2(val);
    byte_t val4 = gmul2(val2);
    byte_t val8 = gmul2(val4);
    return val8 ^ val4 ^ val;
  endfunction

  /**
   * Multiplication in GF(2^8) by 0x0e
   * Used in inverse MixColumns
   */
  function byte_t gmul14(byte_t val);
    byte_t val2 = gmul2(val);
    byte_t val4 = gmul2(val2);
    byte_t val8 = gmul2(val4);
    return val8 ^ val4 ^ val2;
  endfunction

endpackage

