package main

import (
	"context"
	"time"
)

type Context struct {
	data map[any]any
	ctx  context.Context
}

func (c *Context) Set(key any, value any) {
	c.data[key] = value
}

func (c *Context) Deadline() (deadline time.Time, ok bool) {
	return c.ctx.Deadline()
}

func (c *Context) Done() <-chan struct{} {
	return c.ctx.Done()
}

func (c *Context) Err() error {
	return c.ctx.Err()
}

func (c *Context) Value(key any) any {
	return c.data[key]
}

// NewContext creates and initializes a new Context instance with an empty data map and a background context.
func NewContext() *Context {
	return &Context{
		data: make(map[any]any),
		ctx:  context.Background(),
	}
}
