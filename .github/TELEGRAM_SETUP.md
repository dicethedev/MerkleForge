# Telegram Notifications Setup

The repository uses Telegram for daily lines-of-code reports, CI results, and
new or reopened pull request and issue notifications.

## Required Secrets

Add these repository secrets under **Settings → Secrets and variables →
Actions**:

- `TELEGRAM_BOT_TOKEN`: token provided by
  [@BotFather](https://t.me/BotFather).
- `TELEGRAM_CHAT_ID`: production chat, group, or channel ID.
- `TELEGRAM_TEST_CHAT_ID`: optional destination for manual test reports.

The workflows skip Telegram delivery without failing when the required token
or chat ID is missing.

## Workflows

- `daily_loc_report.yml` runs every day at `00:00 UTC` and can also be run
  manually from the Actions tab.
- `telegram_notifications.yml` reports completed CI runs and newly opened or
  reopened pull requests and issues.

Use the manual **Daily Lines of Code Report** workflow with `target=test` and
`post_telegram=true` to verify the bot configuration.
