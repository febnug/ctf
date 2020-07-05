/*
 Solusi LOW_MIPS 
 Newbie CTF 2019
                -- febri
*/

#include <stdio.h>
#include <inttypes.h>
#include <capstone/capstone.h>

int main(void) {
   csh handle; 
   cs_insn *insn;
   size_t count;
   
   char raw_bin[] = "\x27\xBD\xFF\xF8\x20\x20\x00\x0A\x20\x21\x00\x02\xAF\xA1\x00\x00\x20\x41\x00\x04\xAF\xA2\x00\x04\x27\xBD\x00\x08";
   
   if(cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN, &handle) != CS_ERR_OK)
      return -1;
      
   count = cs_disasm(handle, raw_bin, sizeof(raw_bin)-1, 0x1000, 0, &insn);
   
   if(count > 0) {
      size_t j;
      for(j = 0; j < count; j++) {
          printf("0x%"PRIx64": %s %s \n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
      }   
    
          cs_free(insn, count);
    
    } else
          printf("oopps...\n");
          
      cs_close(&handle);
    
    return 0;
}   
