# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

project_root = Path(SPECPATH)
mrgana_root = project_root / 'mrgana'

datas = []

for md_file in mrgana_root.rglob('skills/**/*.md'):
    rel_path = md_file.relative_to(project_root)
    datas.append((str(md_file), str(rel_path.parent)))

for jinja_file in mrgana_root.rglob('agents/**/*.jinja'):
    rel_path = jinja_file.relative_to(project_root)
    datas.append((str(jinja_file), str(rel_path.parent)))

for xml_file in mrgana_root.rglob('*.xml'):
    rel_path = xml_file.relative_to(project_root)
    datas.append((str(xml_file), str(rel_path.parent)))

for tcss_file in mrgana_root.rglob('*.tcss'):
    rel_path = tcss_file.relative_to(project_root)
    datas.append((str(tcss_file), str(rel_path.parent)))

datas += collect_data_files('textual')

datas += collect_data_files('tiktoken')
datas += collect_data_files('tiktoken_ext')

datas += collect_data_files('litellm')

datas += collect_data_files('agents', includes=['**/*.md', '**/*.jinja', '**/*.json'])

hiddenimports = [
    # Core dependencies
    'litellm',
    'litellm.llms',
    'litellm.llms.openai',
    'litellm.llms.anthropic',
    'litellm.llms.vertex_ai',
    'litellm.llms.bedrock',
    'litellm.utils',
    'litellm.caching',

    # Textual TUI
    'textual',
    'textual.app',
    'textual.widgets',
    'textual.containers',
    'textual.screen',
    'textual.binding',
    'textual.reactive',
    'textual.css',
    'textual._text_area_theme',

    # Rich console
    'rich',
    'rich.console',
    'rich.panel',
    'rich.text',
    'rich.markup',
    'rich.style',
    'rich.align',
    'rich.live',

    # Pydantic
    'pydantic',
    'pydantic.fields',
    'pydantic_core',
    'email_validator',

    # Docker
    'docker',
    'docker.api',
    'docker.models',
    'docker.errors',

    # HTTP/Networking
    'httpx',
    'httpcore',
    'requests',
    'urllib3',
    'certifi',

    # Jinja2 templating
    'jinja2',
    'jinja2.ext',
    'markupsafe',

    # XML parsing
    'xmltodict',
    'defusedxml',
    'defusedxml.ElementTree',

    # Syntax highlighting
    'pygments',
    'pygments.lexers',
    'pygments.styles',
    'pygments.util',

    # Tiktoken (for token counting)
    'tiktoken',
    'tiktoken_ext',
    'tiktoken_ext.openai_public',

    # Tenacity retry
    'tenacity',

    # CVSS scoring
    'cvss',

    # Mrgana modules
    'mrgana',
    'mrgana.interface',
    'mrgana.interface.main',
    'mrgana.interface.cli',
    'mrgana.interface.tui',
    'mrgana.interface.tui.app',
    'mrgana.interface.tui.history',
    'mrgana.interface.tui.live_view',
    'mrgana.interface.tui.messages',
    'mrgana.interface.tui.renderers',
    'mrgana.interface.tui.renderers.agent_message_renderer',
    'mrgana.interface.tui.renderers.agents_graph_renderer',
    'mrgana.interface.tui.renderers.base_renderer',
    'mrgana.interface.tui.renderers.finish_renderer',
    'mrgana.interface.tui.renderers.notes_renderer',
    'mrgana.interface.tui.renderers.proxy_renderer',
    'mrgana.interface.tui.renderers.registry',
    'mrgana.interface.tui.renderers.reporting_renderer',
    'mrgana.interface.tui.renderers.thinking_renderer',
    'mrgana.interface.tui.renderers.todo_renderer',
    'mrgana.interface.tui.renderers.user_message_renderer',
    'mrgana.interface.tui.renderers.web_search_renderer',
    'mrgana.interface.utils',
    'mrgana.agents',
    'mrgana.agents.factory',
    'mrgana.agents.prompt',
    'mrgana.config.models',
    'mrgana.core',
    'mrgana.core.agents',
    'mrgana.core.execution',
    'mrgana.core.inputs',
    'mrgana.core.paths',
    'mrgana.core.runner',
    'mrgana.core.sessions',
    'mrgana.report',
    'mrgana.report.dedupe',
    'mrgana.report.state',
    'mrgana.report.writer',
    'mrgana.runtime',
    'mrgana.runtime.backends',
    'mrgana.runtime.caido_bootstrap',
    'mrgana.runtime.docker_client',
    'mrgana.runtime.session_manager',
    'mrgana.telemetry',
    'mrgana.telemetry.logging',
    'mrgana.telemetry.posthog',
    'mrgana.tools',
    'mrgana.tools.agents_graph.tools',
    'mrgana.tools.finish.tool',
    'mrgana.tools.notes.tools',
    'mrgana.tools.proxy._calls',
    'mrgana.tools.proxy.tools',
    'mrgana.tools.python.tool',
    'mrgana.tools.reporting.tool',
    'mrgana.tools.thinking.tool',
    'mrgana.tools.todo.tools',
    'mrgana.tools.web_search.tool',
    'mrgana.skills',
]

hiddenimports += collect_submodules('litellm')
hiddenimports += collect_submodules('textual')
hiddenimports += collect_submodules('rich')
hiddenimports += collect_submodules('pydantic')
hiddenimports += collect_submodules('pygments')

excludes = [
    # Sandbox-only packages
    'playwright',
    'playwright.sync_api',
    'playwright.async_api',
    'IPython',
    'ipython',
    'libtmux',
    'pyte',
    'openhands_aci',
    'openhands-aci',
    'numpydoc',

    # Google Cloud / Vertex AI
    'google.cloud',
    'google.cloud.aiplatform',
    'google.api_core',
    'google.auth',
    'google.oauth2',
    'google.protobuf',
    'grpc',
    'grpcio',
    'grpcio_status',

    # Test frameworks
    'pytest',
    'pytest_asyncio',
    'pytest_cov',
    'pytest_mock',

    # Development tools
    'mypy',
    'ruff',
    'black',
    'isort',
    'pylint',
    'pyright',
    'bandit',
    'pre_commit',

    # Unnecessary for runtime
    'tkinter',
    'matplotlib',
    'numpy',
    'pandas',
    'scipy',
    'PIL',
    'cv2',
]

a = Analysis(
    ['mrgana/interface/main.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='mrgana',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
