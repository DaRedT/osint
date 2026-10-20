# AndroOSINT

Modular OSINT Framework for Android/proot. Combines username search, email lookup, phone analysis, domain recon, and web scraping into a single tool.

## Modules

| Module | Flag | Description |
|---|---|---|
| Username | `-u` | Search username across 35+ platforms |
| Email | `-e` | Email domain analysis + DNS lookup |
| Phone | `-p` | Phone number validation + country detection |
| Domain | `-d` | Subdomain enumeration (crt.sh) + HTTP probe + IP resolution |
| Web | `-w` | Web page scraping (text, links, emails, phones) |

## Usage

```bash
# Single module
python3 osint.py -u johndoe
python3 osint.py -e john@example.com
python3 osint.py -p +49123456789
python3 osint.py -d example.com
python3 osint.py -w https://example.com

# Combined
python3 osint.py -u johndoe -e john@example.com -p +49123456789 -d example.com

# Custom output
python3 osint.py -u johndoe -o /tmp/results
```

## Platforms Checked (Username)
GitHub, Twitter/X, Instagram, Reddit, LinkedIn, YouTube, TikTok, Facebook, Pinterest, Twitch, Medium, Dev.to, HackerNews, GitLab, Bitbucket, StackOverflow, Keybase, Pastebin, Steam, Spotify, SoundCloud, Telegram, Snapchat, Tumblr, WordPress, Blogger, Flickr, Vimeo, Dribbble, Behance, About.me, AngelList, ProductHunt, HackerOne, Bugcrowd

## Android/Termux
- Pure Python (stdlib only, no external deps)
- Works on Termux/proot without root
- Parallel execution for speed

## Legal
OSINT on publicly available data is legal. Do not use for unauthorized access to systems or personal data extraction from individuals without consent. Respect privacy laws (GDPR, etc.).
