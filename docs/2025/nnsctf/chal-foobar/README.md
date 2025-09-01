# CTF Reports (MkDocs + Material)

This repo hosts personal CTF reports/write-ups with reproducible steps.

## Local preview
```bash
pip install mkdocs mkdocs-material mkdocs-git-revision-date-localized-plugin
mkdocs serve
# open http://127.0.0.1:8000
```

## Deploy
Every push to `main` triggers GitHub Actions to build & publish to `gh-pages`.
Site URL (after you replace `<your-user>`):  
`https://<your-user>.github.io/ctf-reports/`
