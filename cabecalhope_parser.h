#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define ASSINATURA_PE 0x4550
#define MAGIC_NUMBER_DOS_OPITIONAL32 0x10b
#define MAGIC_NUMBER_DOS_OPITIONAL32PLUSS 0x20b
#define ASSINATURA_DOS_H 0x5A4D
#define IMAGE_MAGICO_NUMERO_ENTRY 10
#define DIRETORIO_IMAGEM_ENTRY_EXPORT 0
#define DIRETORIO_IMAGEM_ENTRY_IMPORT 0X01
#define DIRETORIO_IMAGEM_ENTRY 0x02
#define NUMERO_TOTAL_DIRETORIOS 16
#define DIRETORIO_IMAGEM_ENTRY_EXCEPTION 0x03
#define DIRETORIO_IMAGEM_ENTRY_SECURITY 0X04
#define DIRETORIO_IMAGEM_ENTRY_BASELOC 0X05
#define DIRETORIO_IMAGEM_ENTRY_DEBUG 0X06
#define DIRETORIO_IMAGEM_ENTRY_ARQUITETURA 0X07
#define DIRETORIO_IMAGEM_ENTRY_PONTGLOBAL 0X08
#define DIRETORIO_IMAGEM_ENTRY_TLS 0X09
#define DIRETORIO_IMAGEM_ENTRY_LOAD_CONFIG 0X0A
#define DIRETORIO_IMAGEM_ENTRY_BOUND_IMPORT 0X0B
#define DIRETORIO_IMAGEM_ENTRY_IAT 0X0C
#define DIRETORIO_IMAGEM_ENTRY_DELAY_IMPORT 0X0D
#define DIRETORIO_IMAGEM_ENTRY_COM_DESCRITOR 0X0E
#define IMAGE_SIZEOF_NOMECURTO 0X08
#define IMAGE_SIZEOF_SECTION_HEADER 0X28

typedef struct meu_DOS{
    uint16_t e_magico;
    uint32_t e_lfnewsjazz;

}__IMAGE_HEADER_WOK, *__PTR_IMAGE_HEADR;

typedef struct caecalho_nt{
    uint16_t valor_maquina;
    uint16_t num_session;
    uint16_t dado_stamp;
    uint32_t pont_pro_simbolo;
    uint32_t num_simbolo;
    uint16_t tamanho_option_h;
    uint16_t caracteristicas;
}__CABECALHO_NT_HEADER, *__PTR_CABECALHO_NT;

typedef struct imagem_dados_diretorios{
    uint32_t endereco_virtual;
    uint32_t tamanho;
}__IMAGEM_DOS_DADOS_DIR, *__PTR__IMAGEM_DOS_DADOS_DIR;

typedef struct cabecalho_nt_opcional_header{
    uint16_t magico;
    uint8_t linker_ver_maior;
    uint8_t linker_ver_menor;
    uint32_t taman_do_code;
    uint32_t tamanh_dos_dados_utilizados;
    uint32_t tamanh_dos_dados_inutilizados;
    uint32_t enderco_pont_entry;
    uint32_t base_do_code;
    uint64_t base_image;
    uint32_t aliagment_sessao;
    uint32_t arq_aliagment;
    uint16_t vers_sys_maior;
    uint16_t vers_sys_menor;
    uint16_t maior_imagemversion;
    uint16_t menor_imagemversion;
    uint16_t subsys_maior;
    uint16_t subsys_menor;
    uint32_t win32_ver_valor;
    uint32_t tamanh_img;
    uint32_t tamanh_header;
    uint32_t checksum;
    uint16_t sub_sys;
    uint16_t caracteristicas_da_dll;
    uint64_t tamanh_stack_reserva;
    uint64_t tamanh_stack_commit;
    uint64_t tamanh_heap_resera;
    uint64_t tamanh_heap_commit;
    uint32_t loade_flag;
    uint32_t num_RVA_e_tamanh;
    __IMAGEM_DOS_DADOS_DIR meu_MS_DOS[NUMERO_TOTAL_DIRETORIOS];
    
}__CABECALHO_NT_HEAD_OPTIONAL, *__PTR_CABECALHO_OPTIONAL_HEADER;

typedef struct section_cabecalho{
    char nome[8];
    uint32_t tamanh_virtual;
    uint32_t endereco_virtual;
    uint32_t tamanh_dados_brutos;
    uint32_t pont_dados_brutos;
    uint32_t pont_pra_relocations;
    uint32_t pont_pra_linennumbers;
    uint16_t num_relocations;
    uint16_t num_linennumbers;
    uint32_t caracteristicas;

}__SECTION_CABECALHO, *__PTR_SECTION_CABECALHO;

typedef union imagem_import_description{
    uint32_t caracteristicas;
    uint32_t primeiro_orginal_thunk;
}__IMAGEM_IMPORT_DESCRIPTION, *__PTR__IMAGEM_IMPORT_DESCRIPTION;

typedef struct tabela_importada{
    __IMAGEM_IMPORT_DESCRIPTION anonimos;
    uint32_t hora_dos_dados_stamp;
    uint32_t forward_corrente;
    uint32_t nome;
    uint32_t prim_thunk;

}__CAECALHO_TABELA_IMPORTADA, *__PTR_CAECALHO_TABELA_IMPORTADA;
