The fixture snippets in `tests/fixtures/{rules,domains_api,net}.py` are extracted from
[Hiddify-Panel](https://github.com/hiddify/Hiddify-Panel), commit
`9f811a25aeac8df9c9995983ff4d8d036cd0ace2` (the Manager 14.2.0 submodule).
They retain the upstream Attribution-NonCommercial-ShareAlike 4.0 license,
reproduced in `tests/fixtures/LICENSE.hiddify`; the toolkit's MIT license does not
relicense those fixtures. Their imports were reduced for isolated offline tests.

The toolkit's patches operate on the separately installed panel source; a panel
installation is not bundled in the toolkit.
