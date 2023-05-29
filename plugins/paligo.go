package plugins

import (
	"fmt"
	"strings"

	"github.com/checkmarx/2ms/lib"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	paligoInstanceFlag = "instance"
	paligoUsernameFlag = "username"
	paligoTokenFlag    = "token"
	paligoFolderFlag   = "folder"
)

var (
	paligoInstanceArg string
	paligoFolderArg   int

	foldersChan   = make(chan lib.Item)
	componentChan = make(chan lib.Component)
)

type PaligoPlugin struct {
	Plugin
	Channels
	username string
	token    string
}

func (p *PaligoPlugin) GetCredentials() (string, string) {
	return p.username, p.token
}

func (p *PaligoPlugin) GetName() string {
	return "paligo"
}

func (p *PaligoPlugin) DefineCommand(channels Channels) (*cobra.Command, error) {
	p.Channels = channels

	command := &cobra.Command{
		Use: fmt.Sprintf("%s --%s %s --%s %s --%s %s",
			p.GetName(),
			paligoInstanceFlag, strings.ToUpper(paligoInstanceFlag),
			paligoUsernameFlag, strings.ToUpper(paligoUsernameFlag),
			paligoTokenFlag, strings.ToUpper(paligoTokenFlag)),
		Short: "Scan Paligo instance",
		Long:  "Scan Paligo instance for sensitive information.",
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Msg("Paligo plugin started")
			p.getItems()
		},
	}

	command.Flags().StringVar(&paligoInstanceArg, paligoInstanceFlag, "", "Paligo instance name [required]")
	err := command.MarkFlagRequired(paligoInstanceFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking flag %s as required: %w", paligoInstanceFlag, err)
	}
	command.Flags().StringVar(&p.username, paligoUsernameFlag, "", "Paligo username [required]")
	err = command.MarkFlagRequired(paligoUsernameFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking flag %s as required: %w", paligoUsernameFlag, err)
	}
	command.Flags().StringVar(&p.token, paligoTokenFlag, "", "Paligo token [required]")
	err = command.MarkFlagRequired(paligoTokenFlag)
	if err != nil {
		return nil, fmt.Errorf("error while marking flag %s as required: %w", paligoTokenFlag, err)
	}
	command.Flags().IntVar(&paligoFolderArg, paligoFolderFlag, 0, "Paligo folder ID")

	return command, nil
}

func (p *PaligoPlugin) getItems() {
	paligoApi := lib.NewPaligoApi(paligoInstanceArg, p.username, p.token)

	p.Channels.WaitGroup.Add(1)
	go p.handleFolders()

	if paligoFolderArg != 0 {
		folder, err := paligoApi.ShowFolder(paligoFolderArg)
		if err != nil {
			log.Error().Err(err).Msg("error while getting folder")
			p.Channels.Errors <- err
		}
		for _, folder := range folder.Children {
			if folder.Type == "component" {
				log.Info().Msgf("Found %s %s", folder.Type, folder.Name)
			} else {
				foldersChan <- folder
			}
		}
	} else {
		folders, err := paligoApi.ListFolders()
		if err != nil {
			log.Error().Err(err).Msg("error while getting folders")
			p.Channels.Errors <- err
		}
		for _, folder := range *folders {
			foldersChan <- folder.Item
		}
	}
}

func (p *PaligoPlugin) handleFolders() {
	defer p.Channels.WaitGroup.Done()

	for folder := range foldersChan {
		log.Info().Msgf("Found folder %s", folder.Name)
	}
}
