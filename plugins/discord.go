package plugins

import (
	"fmt"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/checkmarx/2ms/lib"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	discordTokenFlag         = "discord-token"
	discordServersFlag       = "discord-server"
	discordChannelsFlag      = "discord-channel"
	discordFromDateFlag      = "discord-duration"
	discordMessagesCountFlag = "discord-messages-count"
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
}

func (p *DiscordPlugin) DefineCommandLineArgs(cmd *cobra.Command) error {
	flags := cmd.Flags()

	flags.String(discordTokenFlag, "", "discord token")
	flags.StringArray(discordServersFlag, []string{}, "discord servers")
	flags.StringArray(discordChannelsFlag, []string{}, "discord channels")
	flags.Duration(discordFromDateFlag, defaultDateFrom, "discord from date")
	flags.Int(discordMessagesCountFlag, 0, "discord messages count")

	cmd.MarkFlagsRequiredTogether(discordTokenFlag, discordServersFlag)

	return nil
}

func (p *DiscordPlugin) Initialize(cmd *cobra.Command) error {
	flags := cmd.Flags()
	token, _ := flags.GetString(discordTokenFlag)
	if token == "" {
		return fmt.Errorf("discord token arg is missing. Plugin initialization failed")
	}

	guilds, _ := flags.GetStringArray(discordServersFlag)
	if len(guilds) == 0 {
		return fmt.Errorf("discord servers arg is missing. Plugin initialization failed")
	}

	channels, _ := flags.GetStringArray(discordChannelsFlag)
	if len(channels) == 0 {
		log.Warn().Msg("discord channels not provided. Will scan all channels")
	}

	fromDate, _ := flags.GetDuration(discordFromDateFlag)
	count, _ := flags.GetInt(discordMessagesCountFlag)
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

func (p *DiscordPlugin) GetItems() (*[]Item, error) {

	err := p.getDiscordReady()
	if err != nil {
		return nil, err
	}

	guilds := p.getGuildsByNameOrIDs()
	log.Info().Msgf("Found %d guilds", len(guilds))

	items := lib.ParallelApply(guilds, p.readGuildMessages)

	return items, nil
}

func (p *DiscordPlugin) getDiscordReady() (err error) {
	p.Session, err = discordgo.New(p.Token)
	if err != nil {
		return err
	}

	p.Session.StateEnabled = true
	ready := make(chan int)
	p.Session.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {
		ready <- 1
	})
	err = p.Session.Open()
	if err != nil {
		return err
	}
	<-ready
	return nil
}

func (p *DiscordPlugin) getGuildsByNameOrIDs() []*discordgo.Guild {
	var result []*discordgo.Guild
	if len(p.Guilds) == 0 {
		return p.Session.State.Guilds
	}

	for _, guild := range p.Guilds {
		for _, g := range p.Session.State.Guilds {
			if g.Name == guild || g.ID == guild {
				result = append(result, g)
			}
		}
	}

	return result
}

func (p *DiscordPlugin) readGuildMessages(guild *discordgo.Guild) (*[]Item, error) {
	guildLogger := log.With().Str("guild", guild.Name).Logger()
	guildLogger.Debug().Send()

	selectedChannels := p.getChannelsByNameOrIDs(guild)
	guildLogger.Info().Msgf("Found %d channels", len(selectedChannels))

	items := lib.ParallelApply(selectedChannels, p.readChannelMessages)

	return items, nil
}

func (p *DiscordPlugin) getChannelsByNameOrIDs(guild *discordgo.Guild) []*discordgo.Channel {
	// TODO: is it includes threads?
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

func (p *DiscordPlugin) readChannelMessages(channel *discordgo.Channel) (*[]Item, error) {
	channelLogger := log.With().Str("guildID", channel.GuildID).Str("channel", channel.Name).Logger()
	channelLogger.Debug().Send()

	permission, err := p.Session.UserChannelPermissions(p.Session.State.User.ID, channel.ID)
	if err != nil {
		if err, ok := err.(*discordgo.RESTError); ok {
			if err.Message.Code == 50001 {
				channelLogger.Debug().Msg("No read permissions")
				return nil, nil
			}
		}

		channelLogger.Error().Err(err).Msg("Failed to get permissions")
		return nil, err
	}
	if permission&discordgo.PermissionViewChannel == 0 {
		channelLogger.Debug().Msg("No read permissions")
		return nil, nil
	}
	if channel.Type != discordgo.ChannelTypeGuildText {
		channelLogger.Debug().Msg("Not a text channel")
		return nil, nil
	}

	messages, err := p.getMessages(channel.ID)
	if err != nil {
		channelLogger.Error().Err(err).Msg("Failed to get messages")
		return nil, err
	}
	channelLogger.Info().Msgf("Found %d messages", len(messages))
	return convertMessagesToItems(channel.GuildID, &messages), nil
}

func (p *DiscordPlugin) getMessages(channelID string) ([]*discordgo.Message, error) {
	var messages []*discordgo.Message

	var beforeID string
	for {
		m, err := p.Session.ChannelMessages(channelID, 100, beforeID, "", "")
		if err != nil {
			return nil, err
		}
		if len(m) == 0 {
			break
		}
		messages = append(messages, m...)
		if p.Count > 0 && len(messages) >= p.Count {
			messages = messages[:p.Count]
			log.Debug().Msgf("Reached message count (%d)", p.Count)
			break
		}

		timeSince := time.Since(messages[len(messages)-1].Timestamp)
		if p.BackwardDuration > 0 && timeSince > p.BackwardDuration {
			log.Debug().Msgf("Reached time limit (%s). Last message is %s old", p.BackwardDuration.String(), timeSince.Round(time.Hour).String())
			break
		}
		beforeID = messages[len(messages)-1].ID
	}

	return messages, nil
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
