#include "vec.h"

#include <stdlib.h>

struct vec *vec_create(void) {
  struct vec *v = malloc(sizeof(struct vec));
  if (!v)
    return NULL;

  if (vec_init(v) < 0) {
    free(v);
    return NULL;
  }

  return v;
}

int vec_init(struct vec *v) {
  v->size = 0;
  v->cap = VEC_DEFAULT_CAP;

  v->items = malloc(v->cap * sizeof(void *));
  if (!v->items) {
    return -1;
  }

  return 0;
}

void vec_destroy(struct vec *v) {
  free(v->items);
  free(v);
}

void vec_deinit(struct vec *v) { free(v->items); }

static void extend_vec(struct vec *v) {
  v->cap *= 2;
  v->items = realloc(v->items, v->cap * sizeof(void *));
}

void vec_push_back(struct vec *v, void *el) {
  if (v->size + 1 >= v->cap)
    extend_vec(v);

  v->items[v->size++] = el;
}

void *vec_pop_back(struct vec *v) {
  if (vec_size(v) == 0)
    return NULL;

  void *last = vec_get(v, vec_size(v) - 1);
  v->size--;
  return last;
}

void *vec_get(struct vec *v, size_t i) {
  if (i >= v->size)
    return NULL;

  return v->items[i];
}
