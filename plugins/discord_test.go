package plugins

import (
	"github.com/bwmarrin/discordgo"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetGuildsByNameOrIDs(t *testing.T) {
	tests := []struct {
		name     string
		plugin   DiscordPlugin
		expected []*discordgo.Guild
	}{
		{
			name: "Match only by Name",
			plugin: DiscordPlugin{
				Guilds: []string{"mockGuild1", "mockGuild2"},
				Session: &discordgo.Session{
					State: &discordgo.State{
						Ready: discordgo.Ready{
							Guilds: []*discordgo.Guild{
								{
									Name: "mockGuild0",
									ID:   "123456789012345670",
								},
								{
									Name: "mockGuild1",
									ID:   "123456789012345671",
								},
								{
									Name: "mockGuild2",
									ID:   "123456789012345672",
								},
								{
									Name: "mockGuild4",
									ID:   "123456789012345673",
								},
							},
						},
					},
				},
			},
			expected: []*discordgo.Guild{
				{
					Name: "mockGuild1",
					ID:   "123456789012345671",
				},
				{
					Name: "mockGuild2",
					ID:   "123456789012345672",
				},
			},
		},
		{
			name: "Match only by ID",
			plugin: DiscordPlugin{
				Guilds: []string{"123456789012345671", "123456789012345672"},
				Session: &discordgo.Session{
					State: &discordgo.State{
						Ready: discordgo.Ready{
							Guilds: []*discordgo.Guild{
								{
									Name: "mockGuild0",
									ID:   "123456789012345670",
								},
								{
									Name: "mockGuild1",
									ID:   "123456789012345671",
								},
								{
									Name: "mockGuild2",
									ID:   "123456789012345672",
								},
								{
									Name: "mockGuild4",
									ID:   "123456789012345673",
								},
							},
						},
					},
				},
			},
			expected: []*discordgo.Guild{
				{
					Name: "mockGuild1",
					ID:   "123456789012345671",
				},
				{
					Name: "mockGuild2",
					ID:   "123456789012345672",
				},
			},
		},
		{
			name: "Match by ID and name",
			plugin: DiscordPlugin{
				Guilds: []string{"mockGuild1", "123456789012345672"},
				Session: &discordgo.Session{
					State: &discordgo.State{
						Ready: discordgo.Ready{
							Guilds: []*discordgo.Guild{
								{
									Name: "mockGuild0",
									ID:   "123456789012345670",
								},
								{
									Name: "mockGuild1",
									ID:   "123456789012345671",
								},
								{
									Name: "mockGuild2",
									ID:   "123456789012345672",
								},
								{
									Name: "mockGuild4",
									ID:   "123456789012345673",
								},
							},
						},
					},
				},
			},
			expected: []*discordgo.Guild{
				{
					Name: "mockGuild1",
					ID:   "123456789012345671",
				},
				{
					Name: "mockGuild2",
					ID:   "123456789012345672",
				},
			},
		},
		{
			name: "No match",
			plugin: DiscordPlugin{
				Guilds: []string{"mockGuild5", "123456789012345679"},
				Session: &discordgo.Session{
					State: &discordgo.State{
						Ready: discordgo.Ready{
							Guilds: []*discordgo.Guild{
								{
									Name: "mockGuild0",
									ID:   "123456789012345670",
								},
								{
									Name: "mockGuild4",
									ID:   "123456789012345673",
								},
							},
						},
					},
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plugin.getGuildsByNameOrIDs()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetChannelsByNameOrIDs(t *testing.T) {
	tests := []struct {
		name     string
		plugin   DiscordPlugin
		guild    *discordgo.Guild
		expected []*discordgo.Channel
	}{
		{
			name: "No Channels filtered",
			plugin: DiscordPlugin{
				Channels: []string{},
			},
			guild: &discordgo.Guild{
				Channels: []*discordgo.Channel{
					{
						Name: "mockChannel0",
						ID:   "123456789012345670",
					},
					{
						Name: "mockChannel1",
						ID:   "123456789012345671",
					},
				},
			},
			expected: []*discordgo.Channel{
				{
					Name: "mockChannel0",
					ID:   "123456789012345670",
				},
				{
					Name: "mockChannel1",
					ID:   "123456789012345671",
				},
			},
		},
		{
			name: "Match only by Channel Name",
			plugin: DiscordPlugin{
				Channels: []string{"mockChannel1", "mockChannel2"},
			},
			guild: &discordgo.Guild{
				Channels: []*discordgo.Channel{
					{
						Name: "mockChannel0",
						ID:   "123456789012345670",
					},
					{
						Name: "mockChannel1",
						ID:   "123456789012345671",
					},
					{
						Name: "mockChannel2",
						ID:   "123456789012345672",
					},
					{
						Name: "mockChannel3",
						ID:   "123456789012345673",
					},
				},
			},
			expected: []*discordgo.Channel{
				{
					Name: "mockChannel1",
					ID:   "123456789012345671",
				},
				{
					Name: "mockChannel2",
					ID:   "123456789012345672",
				},
			},
		},
		{
			name: "Match only by Channel ID",
			plugin: DiscordPlugin{
				Channels: []string{"123456789012345671", "123456789012345672"},
			},
			guild: &discordgo.Guild{
				Channels: []*discordgo.Channel{
					{
						Name: "mockChannel0",
						ID:   "123456789012345670",
					},
					{
						Name: "mockChannel1",
						ID:   "123456789012345671",
					},
					{
						Name: "mockChannel2",
						ID:   "123456789012345672",
					},
					{
						Name: "mockChannel3",
						ID:   "123456789012345673",
					},
				},
			},
			expected: []*discordgo.Channel{
				{
					Name: "mockChannel1",
					ID:   "123456789012345671",
				},
				{
					Name: "mockChannel2",
					ID:   "123456789012345672",
				},
			},
		},
		{
			name: "Match only by Name and Channel ID",
			plugin: DiscordPlugin{
				Channels: []string{"123456789012345671", "mockChannel2"},
			},
			guild: &discordgo.Guild{
				Channels: []*discordgo.Channel{
					{
						Name: "mockChannel0",
						ID:   "123456789012345670",
					},
					{
						Name: "mockChannel1",
						ID:   "123456789012345671",
					},
					{
						Name: "mockChannel2",
						ID:   "123456789012345672",
					},
					{
						Name: "mockChannel3",
						ID:   "123456789012345673",
					},
				},
			},
			expected: []*discordgo.Channel{
				{
					Name: "mockChannel1",
					ID:   "123456789012345671",
				},
				{
					Name: "mockChannel2",
					ID:   "123456789012345672",
				},
			},
		},
		{
			name: "No Match",
			plugin: DiscordPlugin{
				Channels: []string{"mockChannel5"},
			},
			guild: &discordgo.Guild{
				Channels: []*discordgo.Channel{
					{
						Name: "mockChannel0",
						ID:   "123456789012345670",
					},
					{
						Name: "mockChannel1",
						ID:   "123456789012345671",
					},
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plugin.getChannelsByNameOrIDs(tt.guild)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertMessagesToItems(t *testing.T) {
	tests := []struct {
		name       string
		pluginName string
		guildId    string
		messages   []*discordgo.Message
		want       []ISourceItem
	}{
		{
			name:       "Multiple messages",
			pluginName: "TestPlugin",
			guildId:    "12345",
			messages: []*discordgo.Message{
				{
					ID:        "67890",
					ChannelID: "112233",
					Content:   "mock content 1",
				},
				{
					ID:        "67891",
					ChannelID: "112234",
					Content:   "mock content 2",
				},
			},
			want: []ISourceItem{
				item{
					Content: ptr("mock content 1"),
					ID:      "TestPlugin-12345-112233-67890",
					Source:  "https://discord.com/channels/12345/112233/67890",
				},
				item{
					Content: ptr("mock content 2"),
					ID:      "TestPlugin-12345-112234-67891",
					Source:  "https://discord.com/channels/12345/112234/67891",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertMessagesToItems(tt.pluginName, tt.guildId, &tt.messages)
			assert.Equal(t, &tt.want, got)
		})
	}
}

func ptr(s string) *string {
	return &s
}
