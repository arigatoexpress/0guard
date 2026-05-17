from guard0.hackquest_public_readback import (
    parse_hackquest_is_submit,
    parse_hackquest_project_html,
)


def test_parse_hackquest_project_html_extracts_links_and_proofs() -> None:
    html = """
    <html>
      <body>
        <a href="https://github.com/arigatoexpress/0guard">repo</a>
        <a href="https://arigatoexpress.github.io/0guard/">demo</a>
        <a href="rariwrldd/status/2054779961425461542">x</a>
        <script id="__NEXT_DATA__">{"props":{"pageProps":{"project":{"isSubmit":true}}}}</script>
        <div>0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc</div>
        <div>https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed</div>
      </body>
    </html>
    """
    repo, demo, x_link, contracts, txs = parse_hackquest_project_html(html)
    assert repo == "https://github.com/arigatoexpress/0guard"
    assert demo == "https://arigatoexpress.github.io/0guard/"
    assert x_link == "https://x.com/rariwrldd/status/2054779961425461542"
    assert parse_hackquest_is_submit(html) is True
    assert "0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc" in contracts
    assert (
        "https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed"
        in txs
    )


def test_parse_hackquest_project_html_prefers_x_status_link() -> None:
    html = """
    <html>
      <body>
        <a href="https://x.com/rariwrldd">profile</a>
        <a href="rariwrldd/status/2054779961425461542">status</a>
      </body>
    </html>
    """
    _, _, x_link, _, _ = parse_hackquest_project_html(html)
    assert x_link == "https://x.com/rariwrldd/status/2054779961425461542"
