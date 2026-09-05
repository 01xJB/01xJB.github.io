# 01xJB.github.io

Source for [01xjb.github.io](https://01xjb.github.io/), a blog of CTF writeups (TryHackMe, HackTheBox) and red team research notes. Built with [Hugo](https://gohugo.io/) and the [Hextra](https://github.com/imfing/hextra) theme, deployed to GitHub Pages via GitHub Actions.

## Local Development

Requires [Hugo (extended)](https://gohugo.io/installation/) and Go.

```bash
hugo mod tidy
hugo server -p 1313
```

## Adding a Writeup

New content goes under `content/writeups/<category>/`. Front matter convention:

```yaml
---
title: "Room or Machine Name"
date: 2026-01-01
weight: 1
type: docs
tags:
  - Some Tag
---
```

Pushing to `main` triggers the deploy workflow automatically.
