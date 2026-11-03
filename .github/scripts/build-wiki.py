#!/usr/bin/env python3
"""Build the GitHub wiki from README.md.

    python3 .github/scripts/build-wiki.py <wiki-checkout-dir>

README.md stays the single source: this splits its numbered sections into
wiki pages, fixes links between them, points images and repository files
at GitHub, and writes Home, _Sidebar and _Footer. Then commit and push the
wiki checkout (git clone https://github.com/CptNope/JAT-Shell-Scanner.wiki.git).
"""
import os
import re
import sys

REPO = 'CptNope/JAT-Shell-Scanner'
BLOB = f'https://github.com/{REPO}/blob/main/'
RAW = f'https://raw.githubusercontent.com/{REPO}/main/'

# Wiki page -> README section numbers, in sidebar order.
PAGES = [
    ('For site owners', [
        ('PHP2Shell-and-wp2shell', 'PHP2Shell and wp2shell', [1, 2]),
        ('Install-and-Scan', 'Install, scan and update', [3, 10]),
        ('Understanding-Your-Results', 'Understanding your results', [4, 5, 8]),
        ('What-It-Checks', 'What it checks', [6]),
        ('Settings-and-Alerts', 'Settings and alerts', [7]),
        ('If-Your-Site-Is-Compromised', 'If your site is compromised', [9]),
        ('Troubleshooting', 'Troubleshooting, logs and hosting', [11, 15, 16]),
        ('FAQ', 'FAQ', [12]),
    ]),
    ('For agencies and developers', [
        ('WP-CLI', 'WP-CLI', [13]),
        ('Fleet-Dashboard', 'Scanning many sites', [14]),
        ('How-It-Works', 'How it works, privacy and limits', [17, 18, 22]),
        ('For-Developers', 'Hooks, report format and development', [19, 20, 21, 23]),
        ('Sources-and-License', 'Sources and license', [24, 25]),
    ]),
]


def slug(text):
    """GitHub's heading anchor."""
    text = re.sub(r'<[^>]+>', '', text).strip().lower()
    text = re.sub(r'[^\w\- ]', '', text)
    return text.replace(' ', '-')


def split_sections(lines):
    """Header block, then {number or name: (title, body lines)}."""
    header, sections, cur = [], {}, None
    for line in lines:
        m = re.match(r'^## (?:(\d+)\. )?(.+)$', line)
        if m:
            cur = int(m.group(1)) if m.group(1) else m.group(2).strip()
            sections[cur] = (m.group(2).strip(), [])
            continue
        (header if cur is None else sections[cur][1]).append(line)
    return header, sections


def main(out):
    readme = open('README.md', encoding='utf-8').read().splitlines()
    header, sections = split_sections(readme)

    # Where each README anchor ends up: (page, anchor or None).
    where = {}
    for _, pages in PAGES:
        for page, _, nums in pages:
            for n in nums:
                title, body = sections[n]
                where[slug(f'{n}. {title}')] = (page, None if len(nums) == 1 else slug(title))
                for line in body:
                    h = re.match(r'^#{3,6} (.+)$', line)
                    if h:
                        where[slug(h.group(1))] = (page, slug(h.group(1)))
    where['whats-new'] = ('Home', 'whats-new')

    def fix_link(target):
        if target.startswith('#'):
            page, anchor = where.get(target[1:], ('Home', None))
            return page + ('#' + anchor if anchor else '')
        if re.match(r'^[a-z]+:', target) or target.startswith('/'):
            return target
        path = target.lstrip('./')
        return (RAW if path.startswith('docs/images/') else BLOB) + path

    def fix(lines):
        out_lines, fence = [], False
        for line in lines:
            if line.lstrip().startswith('```'):
                fence = not fence
            if not fence:
                line = re.sub(r'\]\(([^)\s]+)\)', lambda m: '](' + fix_link(m.group(1)) + ')', line)
                line = re.sub(r'(src|href)="([^"]+)"', lambda m: f'{m.group(1)}="{fix_link(m.group(2))}"', line)
            out_lines.append(line)
        while out_lines and out_lines[-1].strip() in ('', '---'):
            out_lines.pop()
        while out_lines and not out_lines[0].strip():
            out_lines.pop(0)
        return out_lines

    os.makedirs(out, exist_ok=True)
    written = []

    def write(name, lines):
        with open(os.path.join(out, name + '.md'), 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines).rstrip() + '\n')
        written.append(name)

    for _, pages in PAGES:
        for page, _, nums in pages:
            lines = []
            for n in nums:
                title, body = sections[n]
                if len(nums) > 1:
                    lines += ['', f'## {title}', '']
                lines += fix(body)
            write(page, fix(lines))

    # Home: the README's header and What's new, then the page list.
    home = fix(header) + ['', '## What\'s new', ''] + fix(sections["What's new"][1]) + ['', '## In this wiki', '']
    for group, pages in PAGES:
        home += ['', f'**{group}**', '']
        home += [f'- [{label}]({page})' for page, label, _ in pages]
    write('Home', home)

    sidebar = ['**[Home](Home)**', '']
    for group, pages in PAGES:
        sidebar += [f'**{group}**', ''] + [f'- [{label}]({page})' for page, label, _ in pages] + ['']
    sidebar += ['**Links**', '', f'- [Download the latest release](https://github.com/{REPO}/releases/latest)',
                '- [WordPress.org page](https://wordpress.org/plugins/jat-shell-scanner/)',
                f'- [Changelog]({BLOB}CHANGELOG.md)', '- [Jeremy Anderson Tech](https://jeremyanderson.tech/)']
    write('_Sidebar', sidebar)
    write('_Footer', [f'This wiki is built from the repository\'s [README.md]({BLOB}README.md) by '
                      f'`.github/scripts/build-wiki.py`. To change a page, edit README.md: '
                      'edits made here are replaced the next time the wiki is rebuilt.'])
    print('Wrote ' + ', '.join(written))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
