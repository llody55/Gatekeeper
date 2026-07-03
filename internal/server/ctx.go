package server

import "context"

type actorKey struct{}

func setCtx(ctx context.Context, ac AuthCtx) context.Context {
	return context.WithValue(ctx, actorKey{}, ac)
}

func getCtx(ctx context.Context) (AuthCtx, bool) {
	v, ok := ctx.Value(actorKey{}).(AuthCtx)
	return v, ok
}
