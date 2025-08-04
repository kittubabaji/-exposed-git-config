id: exposed-git-config

info:
  name: Exposed .git/config File
  author: Curious_Hunter(SurendraWadiwa)
  severity: medium
  description: Detects exposed .git/config files which may reveal repository origin URLs, configuration, and internal development information.
  tags: git,exposure,files,leak,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"

    headers:
      User-Agent: nuclei-git-checker

    matchers:
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion"
        condition: and

    matchers-condition: and

