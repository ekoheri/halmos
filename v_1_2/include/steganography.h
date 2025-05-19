#ifndef STEGANOGRAPHY_H
#define STEGANOGRAPHY_H

int Inject(const char *filecover, const char *filestego,const char *message);
char* Extract(const char *filestego); 

#endif