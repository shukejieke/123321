package main

import (
	"context"
	"fmt"
	"stzbHelper/global"
	"stzbHelper/model"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

func (a *App) GetTeamUser() string {
	var teamUsers []model.TeamUser
	query := model.Conn
	query.Find(&teamUsers)

	return global.Response{Data: teamUsers}.Success()
}

func (a *App) GetNetData() string {
	return global.Response{Data: Data}.Success()
}

func (a *App) ClearNetData() string {
	Data = []NetData{}
	return "ok"
}
