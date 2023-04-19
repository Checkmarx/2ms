package plugins

import (
	"fmt"

	"github.com/bwmarrin/discordgo"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// const userID = "679192513541570570"
const serverName = "2ms testing"
const channelName = "general"
const token = ""

type DiscordPlugin struct{}

func (p *DiscordPlugin) DefineCommandLineArgs(cmd *cobra.Command) error {
	// TODO: get server, channel, from date, messages count
	return nil
}

func (p *DiscordPlugin) Initialize(cmd *cobra.Command) error {
	return nil
}

func (p *DiscordPlugin) GetItems() (*[]Item, error) {

	items := []Item{}

	discord, err := getDiscordReady(token)
	if err != nil {
		return nil, err
	}

	guilds := getGuildsByNameOrIDs(discord, []string{serverName})
	for _, guild := range guilds {
		// TODO use go routines
		messages, err := readGuildMessages(discord, guild, []string{ /*channelName*/ })
		if err != nil {
			return nil, err
		}
		items = append(items, *messages...)
	}

	return &items, nil
}

func getDiscordReady(token string) (*discordgo.Session, error) {
	discord, err := discordgo.New(token)
	if err != nil {
		return nil, err
	}

	discord.StateEnabled = true
	ready := make(chan int)
	discord.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {
		ready <- 1
	})
	err = discord.Open()
	if err != nil {
		return nil, err
	}
	<-ready
	return discord, nil
}

func getGuildsByNameOrIDs(discord *discordgo.Session, guilds []string) []*discordgo.Guild {
	var result []*discordgo.Guild
	if len(guilds) == 0 {
		return discord.State.Guilds
	}

	for _, guild := range guilds {
		for _, g := range discord.State.Guilds {
			if g.Name == guild || g.ID == guild {
				result = append(result, g)
			}
		}
	}

	return result
}

func getChannelsByNameOrIDs(discord *discordgo.Session, guild *discordgo.Guild, channels []string) []*discordgo.Channel {
	var result []*discordgo.Channel
	if len(channels) == 0 {
		return guild.Channels
	}

	for _, channel := range channels {
		for _, c := range guild.Channels {
			if c.Name == channel || c.ID == channel {
				result = append(result, c)
			}
		}
	}

	return result
}

func readGuildMessages(discord *discordgo.Session, guild *discordgo.Guild, channels []string) (*[]Item, error) {
	guildLogger := log.With().Str("guild", guild.Name).Logger()
	guildLogger.Debug().Send()

	selectedChannels := getChannelsByNameOrIDs(discord, guild, channels)

	items := []Item{}

	for _, channel := range selectedChannels {
		messages, err := readChannelMessages(guildLogger, discord, channel)
		if err != nil {
			return nil, err
		}
		if messages != nil {
			items = append(items, *messages...)
		}
	}

	return &items, nil
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

func readChannelMessages(logger zerolog.Logger, discord *discordgo.Session, channel *discordgo.Channel) (*[]Item, error) {
	channelLogger := logger.With().Str("channel", channel.Name).Logger()
	channelLogger.Debug().Send()

	permission, err := discord.UserChannelPermissions(discord.State.User.ID, channel.ID)
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
	// TODO read all messages
	messages, err := discord.ChannelMessages(channel.ID, 100, "", "", "")
	if err != nil {
		channelLogger.Error().Err(err).Msg("Failed to get messages")
		return nil, err
	}
	if len(messages) == 0 {
		channelLogger.Debug().Msg("No messages")
		return nil, nil
	}
	channelLogger.Debug().Msgf("Got last message: %s", messages[0].Content)
	return convertMessagesToItems(channel.GuildID, &messages), nil
}

func (p *DiscordPlugin) IsEnabled() bool {
	return true
}

func getMessages(s *discordgo.Session, channelID string) ([]*discordgo.Message, error) {
	var messages []*discordgo.Message
	var beforeID string
	for {
		msgs, err := s.ChannelMessages(channelID, 100, beforeID, "", "")
		if err != nil {
			return nil, err
		}
		if len(msgs) == 0 {
			break
		}
		messages = append(messages, msgs...)
		beforeID = msgs[len(msgs)-1].ID
	}
	return messages, nil
}
