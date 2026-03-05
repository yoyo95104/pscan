#define _GNU_SOURCE
#include "mod.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

char *parse_filter(struct filter_args *f) {
  static char param[256];
  param[0] = '\0';

  if (f->ip != NULL) {
    strncat(param, "ip=", sizeof(param) - strlen(param) - 1);
    strncat(param, f->ip, sizeof(param) - strlen(param) - 1);
    strncat(param, " ", sizeof(param) - strlen(param) - 1);
  }
  if (f->dip != NULL) {
    strncat(param, "dip=", sizeof(param) - strlen(param) - 1);
    strncat(param, f->dip, sizeof(param) - strlen(param) - 1);
    strncat(param, " ", sizeof(param) - strlen(param) - 1);
  }
  if (f->targetport > 0) {
    char seg[32];
    snprintf(seg, sizeof(seg), "targetport=%u ", f->targetport);
    strncat(param, seg, sizeof(param) - strlen(param) - 1);
  }
  if (f->proto > 0) {
    char seg[32];
    snprintf(seg, sizeof(seg), "proto=%u ", f->proto);
    strncat(param, seg, sizeof(param) - strlen(param) - 1);
  }
  if (f->startrange > 0) {
    char seg[32];
    snprintf(seg, sizeof(seg), "rangestart=%u ", f->startrange);
    strncat(param, seg, sizeof(param) - strlen(param) - 1);
  }
  if (f->endrange > 0) {
    char seg[32];
    snprintf(seg, sizeof(seg), "rangeend=%u", f->endrange);
    strncat(param, seg, sizeof(param) - strlen(param) - 1);
  }

  int len = strlen(param);
  if (len > 0 && param[len - 1] == ' ')
    param[len - 1] = '\0';
  return param;
}

void parse_filter_string(const char *filter_str, struct filter_args *f) {
  f->ip = NULL;
  f->dip = NULL;
  f->proto = 0;
  f->targetport = 0;
  f->endrange = 0;
  f->startrange = 0;
  char *copy = strdup(filter_str);
  char *token = strtok(copy, ",");
  while (token != NULL) {
    char *eq = strchr(token, '=');
    if (eq) {
      *eq = '\0';
      char *key = token;
      char *val = eq + 1;
      if (strcmp(key, "ip") == 0 && strcmp(val, "NULL") != 0)
        f->ip = strdup(val);
      else if (strcmp(key, "dip") == 0 && strcmp(val, "NULL") != 0)
        f->dip = strdup(val);
      else if (strcmp(key, "targetport") == 0)
        f->targetport = atoi(val);
      else if (strcmp(key, "proto") == 0)
        f->proto = atoi(val);
      else if (strcmp(key, "startrange") == 0)
        f->startrange = atoi(val);
      else if (strcmp(key, "endrange") == 0)
        f->endrange = atoi(val);
    }
    token = strtok(NULL, ",");
  }
  free(copy);
}

int load_module(char *f) {
  int fd = open("filter.ko", O_RDONLY);
  if (fd < 0) {
    perror("Loading NetFilter Module");
    return -1;
  }
  if (syscall(SYS_finit_module, fd, f, 0) != 0) {
    perror("finit_module failed");
    close(fd);
    return -1;
  }
  printf("\nLoaded Module with: %s\n", f);
  close(fd);
  return 0;
}

void unload_module() {
  int ret = syscall(SYS_delete_module, "filter", O_NONBLOCK);
  if (ret != 0) {
    perror("delete_module");
    fprintf(stderr, "Please Restart Your Device To Unload The Module");
  }
  printf("Unloaded Module\n");
}
