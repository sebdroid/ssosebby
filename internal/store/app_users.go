package store

import (
	"context"
	"fmt"

	"github.com/sebdroid/ssosebby/internal/authn"
	ssoreadyv1 "github.com/sebdroid/ssosebby/internal/gen/ssoready/v1"
	"github.com/sebdroid/ssosebby/internal/store/idformat"
)

func (s *Store) ListAppUsers(ctx context.Context, req *ssoreadyv1.ListAppUsersRequest) (*ssoreadyv1.ListAppUsersResponse, error) {
	qAppUsers, err := s.q.ListAppUsers(ctx, authn.AppOrgID(ctx))
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	var appUsers []*ssoreadyv1.AppUser
	for _, qAppUser := range qAppUsers {
		appUsers = append(appUsers, &ssoreadyv1.AppUser{
			Id:          idformat.AppUser.Format(qAppUser.ID),
			DisplayName: qAppUser.DisplayName,
			Email:       qAppUser.Email,
		})
	}

	return &ssoreadyv1.ListAppUsersResponse{AppUsers: appUsers}, nil
}
