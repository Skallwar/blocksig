#ifndef VEC_H
#define VEC_H

#include <stddef.h>

#define VEC_DEFAULT_CAP 8

struct vec
{
    size_t size;
    size_t cap;
    void **items;
};

struct vec *vec_create(void);
int vec_init(struct vec *v);
void vec_destroy(struct vec *v);
void vec_deinit(struct vec *v);
void vec_push_back(struct vec *v, void *el);
void *vec_pop_back(struct vec *v);
void *vec_get(struct vec *v, size_t i);

static inline size_t vec_size(struct vec *v)
{
    return v->size;
}

#endif /* ! VEC_H */
