#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cabecalhope_parser.h"

__PTR_SECTION_CABECALHO conversaoRVA(int offset, uint32_t RVA, __PTR_SECTION_CABECALHO section, __PTR_CABECALHO_NT nt){

    offset = 0;

    for (int i = 0; i<nt->num_session; i++){
        uint32_t endereco = section[i].endereco_virtual;
        uint32_t tamanho = section[i].tamanh_virtual;

        if (tamanho == 0){
            tamanho = section[i].tamanh_dados_brutos;
        }

        if (RVA >= endereco && RVA < endereco + tamanho){

            offset = RVA - section->endereco_virtual + section->pont_dados_brutos;

            printf("Offset exato do RVA %d \n", offset);

            return &section[i];
        }
    }

    return NULL;

}

int main(void){
    __IMAGE_HEADER_WOK vari;
    __CABECALHO_NT_HEADER cabeca_nt;
    __CABECALHO_NT_HEAD_OPTIONAL variopt;
    int offset = 0; //EU JÁ TENHO TODAS AS FUNÇÕES PARA ESTE PROJETO

    FILE *pont_arqPE;

    pont_arqPE = fopen("arquivo.dll", "rb"); 

    if (pont_arqPE == NULL){
        printf("Houve um erro ao ler o arq binario \n");
    }else{
        size_t consigo = fread(&vari, sizeof(__IMAGE_HEADER_WOK), 1, pont_arqPE);

        if (vari.e_magico == ASSINATURA_DOS_H){
            printf("tem o MZ \n");

            int talvez_mover = fseek(pont_arqPE, 0x3C, SEEK_SET);

            size_t mais_um = fread(&vari.e_lfnewsjazz, sizeof(uint32_t), 1, pont_arqPE);

            int vamosver = fseek(pont_arqPE, vari.e_lfnewsjazz, SEEK_SET);

            long atila = ftell(pont_arqPE);

            printf("tem assinatura dos h %ld\n", atila);

            size_t hmm = fread(&vari.e_lfnewsjazz, sizeof(ASSINATURA_PE), 1, pont_arqPE);

            if (vari.e_lfnewsjazz == ASSINATURA_PE){
                printf("parecido 0x%x \n", vari.e_lfnewsjazz);

                size_t ledo_maq = fread(&cabeca_nt, sizeof(__CABECALHO_NT_HEADER), 1, pont_arqPE);

                long aquila = ftell(pont_arqPE);

                printf("%d \n", aquila);

                printf("tamnaho opt: %u \n", cabeca_nt.tamanho_option_h);
                printf("%zu\n", sizeof(__CABECALHO_NT_HEAD_OPTIONAL));

                if (cabeca_nt.valor_maquina == 0x8664){
                    printf("e de 64 bits \n");

                    size_t indonopt = fread(&variopt, sizeof(__CABECALHO_NT_HEAD_OPTIONAL), 1, pont_arqPE);

                    if (variopt.magico == MAGIC_NUMBER_DOS_OPITIONAL32PLUSS){
                        printf("tem o ox20b: 0x%x\n", variopt.magico);

                       __SECTION_CABECALHO *mallocado = malloc(cabeca_nt.num_session * sizeof(__SECTION_CABECALHO));

                       if (mallocado == NULL){
                        printf("Houve um erro com o malloc \n");

                        free(mallocado);

                        return 1;
                       }else{
                        printf("Tudo certo com o malloc \n");
                       }

                       for (int i = 0; i<cabeca_nt.num_session; i++){
                            size_t vendo_sessao = fread(&mallocado[i], sizeof(__SECTION_CABECALHO), 1, pont_arqPE);

                            printf("nome section: %.8s \n", mallocado[i].nome);
                       }
                       
                       __PTR_SECTION_CABECALHO converte = conversaoRVA(offset, variopt.enderco_pont_entry, mallocado, &cabeca_nt);
                       
                       if (converte == NULL){
                            printf("error \n");

                            free(mallocado);
                            
                            return 0;
                       }else{
                        printf("fim \n");

                        free(mallocado);
                       }
                    
                    }else{
                        printf("BURRO 0x%x\n", variopt.magico);
                    }

                }else if(cabeca_nt.valor_maquina == 0x014c){
                    printf("e de 32 bits \n");
                }else{
                    printf("Houve m ero inesperado \n");
                }

            }else{
                printf("nao e 0x%x \n", vari.e_lfnewsjazz);
            }

        }else{
            printf("Nao tem 2 bytes. \n");

            return 0;
        }
        
    }
}
