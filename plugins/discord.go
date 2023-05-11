package plugins

import (
	"fmt"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	tokenFlag         = "token"
	serversFlag       = "server"
	channelsFlag      = "channel"
	fromDateFlag      = "duration"
	messagesCountFlag = "messages-count"
)

const defaultDateFrom = time.Hour * 24 * 14

type DiscordPlugin struct {
	Enabled          bool
	Token            string
	Guilds           []string
	Channels         []string
	Count            int
	BackwardDuration time.Duration
	Session          *discordgo.Session

	errChan   chan error
	itemChan  chan Item
	waitGroup *sync.WaitGroup
}

func (p *DiscordPlugin) DefineCommand(channels Channels) *cobra.Command {
	var discordCmd = &cobra.Command{
		Use:   "discord",
		Short: "Scan discord",
	}
	flags := discordCmd.Flags()

	flags.String(tokenFlag, "", "discord token")
	flags.StringArray(serversFlag, []string{}, "discord servers")
	flags.StringArray(channelsFlag, []string{}, "discord channels")
	flags.Duration(fromDateFlag, defaultDateFrom, "discord from date")
	flags.Int(messagesCountFlag, 0, "discord messages count")

	err := discordCmd.MarkFlagRequired(tokenFlag)
	if err != nil {
		log.Fatal().Err(err).Msg("error while marking flag as required")
	}
	err = discordCmd.MarkFlagRequired(serversFlag)
	if err != nil {
		log.Fatal().Err(err).Msg("error while marking flag as required")
	}

	discordCmd.Run = func(cmd *cobra.Command, args []string) {
		err := p.Initialize(cmd)
		if err != nil {
			log.Fatal().Msg(err.Error())
		}

		p.GetItems(channels.Items, channels.Errors, channels.WaitGroup)
	}

	return discordCmd
}

func (p *DiscordPlugin) Initialize(cmd *cobra.Command) error {
	flags := cmd.Flags()
	token, _ := flags.GetString(tokenFlag)
	if token == "" {
		return fmt.Errorf("discord token arg is missing. Plugin initialization failed")
	}

	guilds, _ := flags.GetStringArray(serversFlag)
	if len(guilds) == 0 {
		return fmt.Errorf("discord servers arg is missing. Plugin initialization failed")
	}

	channels, _ := flags.GetStringArray(channelsFlag)
	if len(channels) == 0 {
		log.Warn().Msg("discord channels not provided. Will scan all channels")
	}

	fromDate, _ := flags.GetDuration(fromDateFlag)
	count, _ := flags.GetInt(messagesCountFlag)
	if count == 0 && fromDate == 0 {
		return fmt.Errorf("discord messages count or from date arg is missing. Plugin initialization failed")
	}

	p.Token = token
	p.Guilds = guilds
	p.Channels = channels
	p.Count = count
	p.BackwardDuration = fromDate
	p.Enabled = true

	return nil
}

func (p *DiscordPlugin) IsEnabled() bool {
	return p.Enabled
}

func (p *DiscordPlugin) GetItems(itemsChan chan Item, errChan chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	p.errChan = errChan
	p.itemChan = itemsChan
	p.waitGroup = wg

	err := p.getDiscordReady()
	if err != nil {
		errChan <- err
		return
	}

	guilds := p.getGuildsByNameOrIDs()
	log.Info().Msgf("Found %d guilds", len(guilds))

	wg.Add(len(guilds))
	for _, guild := range guilds {
		go p.readGuildMessages(guild)
	}
}

func (p *DiscordPlugin) getDiscordReady() (err error) {
	p.Session, err = discordgo.New(p.Token)
	if err != nil {
		return err
	}

	p.Session.StateEnabled = true
	ready := make(chan error)
	p.Session.AddHandlerOnce(func(s *discordgo.Session, r *discordgo.Ready) {
		ready <- nil
	})
	go func() {
		err := p.Session.Open()
		if err != nil {
			ready <- err
		}
	}()
	time.AfterFunc(time.Second*10, func() {
		ready <- fmt.Errorf("discord session timeout")
	})

	err = <-ready
	if err != nil {
		return err
	}

	return nil
}

func (p *DiscordPlugin) getGuildsByNameOrIDs() []*discordgo.Guild {
	var result []*discordgo.Guild

	for _, guild := range p.Guilds {
		for _, g := range p.Session.State.Guilds {
			if g.Name == guild || g.ID == guild {
				result = append(result, g)
			}
		}
	}

	return result
}

func (p *DiscordPlugin) readGuildMessages(guild *discordgo.Guild) {
	defer p.waitGroup.Done()

	guildLogger := log.With().Str("guild", guild.Name).Logger()
	guildLogger.Debug().Send()

	selectedChannels := p.getChannelsByNameOrIDs(guild)
	guildLogger.Info().Msgf("Found %d channels", len(selectedChannels))

	p.waitGroup.Add(len(selectedChannels))
	for _, channel := range selectedChannels {
		go p.readChannelMessages(channel)
	}
}

func (p *DiscordPlugin) getChannelsByNameOrIDs(guild *discordgo.Guild) []*discordgo.Channel {
	var result []*discordgo.Channel
	if len(p.Channels) == 0 {
		return guild.Channels
	}

	for _, channel := range p.Channels {
		for _, c := range guild.Channels {
			if c.Name == channel || c.ID == channel {
				result = append(result, c)
			}
		}
	}

	return result
}

func (p *DiscordPlugin) readChannelMessages(channel *discordgo.Channel) {
	defer p.waitGroup.Done()

	channelLogger := log.With().Str("guildID", channel.GuildID).Str("channel", channel.Name).Logger()
	channelLogger.Debug().Send()

	permission, err := p.Session.UserChannelPermissions(p.Session.State.User.ID, channel.ID)
	if err != nil {
		if err, ok := err.(*discordgo.RESTError); ok {
			if err.Message.Code == 50001 {
				channelLogger.Debug().Msg("No read permissions")
				return
			}
		}

		channelLogger.Error().Err(err).Msg("Failed to get permissions")
		p.errChan <- err
		return
	}
	if permission&discordgo.PermissionViewChannel == 0 {
		channelLogger.Debug().Msg("No read permissions")
		return
	}
	if channel.Type != discordgo.ChannelTypeGuildText {
		channelLogger.Debug().Msg("Not a text channel")
		return
	}

	messages, err := p.getMessages(channel.ID, channelLogger)
	if err != nil {
		channelLogger.Error().Err(err).Msg("Failed to get messages")
		p.errChan <- err
		return
	}
	channelLogger.Info().Msgf("Found %d messages", len(messages))

	items := convertMessagesToItems(channel.GuildID, &messages)
	for _, item := range *items {
		p.itemChan <- item
	}
}

func (p *DiscordPlugin) getMessages(channelID string, logger zerolog.Logger) ([]*discordgo.Message, error) {
	var messages []*discordgo.Message
	threadMessages := []*discordgo.Message{}

	var beforeID string

	m, err := p.Session.ChannelMessages(channelID, 100, beforeID, "", "")
	if err != nil {
		return nil, err
	}

	lastMessage := false
	for len(m) > 0 && !lastMessage {

		for _, message := range m {

			timeSince := time.Since(message.Timestamp)
			if p.BackwardDuration > 0 && timeSince > p.BackwardDuration {
				logger.Debug().Msgf("Reached time limit (%s). Last message is %s old", p.BackwardDuration.String(), timeSince.Round(time.Hour).String())
				lastMessage = true
				break
			}

			if p.Count > 0 && len(messages) == p.Count {
				logger.Debug().Msgf("Reached message count (%d)", p.Count)
				lastMessage = true
				break
			}

			if message.Thread != nil {
				logger.Info().Msgf("Found thread %s", message.Thread.Name)
				tMgs, err := p.getMessages(message.Thread.ID, logger.With().Str("thread", message.Thread.Name).Logger())
				if err != nil {
					return nil, err
				}
				threadMessages = append(threadMessages, tMgs...)
			}

			messages = append(messages, message)
			beforeID = message.ID
		}

		m, err = p.Session.ChannelMessages(channelID, 100, beforeID, "", "")
		if err != nil {
			return nil, err
		}
	}

	return append(messages, threadMessages...), nil
}

func convertMessagesToItems(guildId string, messages *[]*discordgo.Message) *[]Item {
	items := []Item{}
	for _, message := range *messages {
		items = append(items, Item{
			Content: message.Content,
			Source:  fmt.Sprintf("https://discord.com/channels/%s/%s/%s", guildId, message.ChannelID, message.ID),
			ID:      message.ID,
		})
	}
	return &items
}
