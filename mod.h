#ifndef MOD_H
#define MOD_H

struct filter_args {
  char *ip;
  char *dip;
  int proto;
  int targetport;
  int startrange;
  int endrange;
};

int load_module(char *f);
void parse_filter_string(const char *filter_str, struct filter_args *f);
void unload_module();
char *parse_filter(struct filter_args *f);

#endif
