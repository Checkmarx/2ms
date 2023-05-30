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
)

type PaligoPlugin struct {
	Plugin
	Channels

	username string
	token    string

	paligoApi *lib.Paligo
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
	p.paligoApi = lib.NewPaligoApi(paligoInstanceArg, p.username, p.token)

	if paligoFolderArg != 0 {
		p.WaitGroup.Add(1)
		go p.handleFolderChildren(lib.Item{ID: paligoFolderArg, Name: "ID" + fmt.Sprint(paligoFolderArg)})
	} else {
		folders, err := p.paligoApi.ListFolders()
		if err != nil {
			log.Error().Err(err).Msg("error while getting folders")
			p.Channels.Errors <- err
			return
		}
		p.WaitGroup.Add(len(*folders))
		for _, folder := range *folders {
			go p.handleFolderChildren(folder.Item)
		}
	}
}

func (p *PaligoPlugin) handleFolderChildren(folder lib.Item) {
	defer p.Channels.WaitGroup.Done()

	log.Info().Msgf("Getting folder %s", folder.Name)
	folderInfo, err := p.paligoApi.ShowFolder(folder.ID)
	if err != nil {
		log.Error().Err(err).Msgf("error while getting %s '%s'", folder.Type, folder.Name)
		p.Channels.Errors <- err
		return
	}

	for _, child := range folderInfo.Children {
		if child.Type == "component" {
			p.WaitGroup.Add(1)
			go p.handleComponent(child)
		} else if child.Type == "folder" {
			p.WaitGroup.Add(1)
			go p.handleFolderChildren(child)
		}
	}

}

func (p *PaligoPlugin) handleComponent(item lib.Item) {
	defer p.Channels.WaitGroup.Done()

	log.Info().Msgf("Getting component %s", item.Name)
	document, err := p.paligoApi.ShowDocument(item.ID)
	if err != nil {
		log.Error().Err(err).Msgf("error while getting document '%s'", item.Name)
		p.Channels.Errors <- fmt.Errorf("error while getting document '%s': %w", item.Name, err)
		return
	}

	p.Items <- Item{
		Content: document.Content,
		Source:  item.Name,
		ID:      fmt.Sprint(item.ID),
	}
}
