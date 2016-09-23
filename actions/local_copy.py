
# Ansible action plugin to write the contents of a variable to a local
# file, optionally vault-encrypting the contents.

import hashlib, json, os, re, sys, traceback

from ansible.parsing.vault import VaultLib
from ansible.plugins.action import ActionBase
from ansible.utils.display import Display


E_ALREADYCRYPT = 'Content is already encrypted! Aborting.'

display = Display()


def fail(msg):
    return dict(failed=True, msg=msg)


class ActionModule(ActionBase):

    ARGS = set(['dest', 'content'])

    def __init__(self, *n, **kw):
        ctx = kw.get('play_context')
        if ctx:
            ctx.no_log = False
        ActionBase.__init__(self, *n, **kw)

    def check_args(self, names, collection):
        for arg in names:
            if arg not in collection:
                return fail('%r is a required argument' % arg)

    def run(self, tmp=None, task_vars=None):
        try:
            return self._run(tmp, task_vars)
        except Exception as e:
            # since this action always runs in no_log=True mode, manually
            # print the real exception, if any.
            display.error(traceback.format_exc())
            return fail('Failed!')

    def _run(self, tmp=None, task_vars=None):
        err = self.check_args(self.ARGS, self._task.args)
        if err:
            return err

        getarg = lambda n, d=None: self._task.args.get(n, d)
        
        dest = getarg('dest')
        content = getarg('content')
        encrypt = getarg('encrypt', False)
        if isinstance(encrypt, basestring):
            encrypt = encrypt in ('yes', 'true', '1')

        if encrypt:
            password = self._task._loader._vault_password
            vault = VaultLib(password=password)
            if vault.is_encrypted(content):
                return fail(E_ALREADYCRYPT)
            content = vault.encrypt(content)

        root = self._loader.get_basedir()
        if self._task._role is not None:
            root = self._task._role._role_path

        outpath = os.path.join(root, dest)
        parent = os.path.dirname(outpath)
        if not os.path.exists(parent):
            os.makedirs(parent)

        open(outpath, 'wb').write(content)

        return dict(path=outpath)

