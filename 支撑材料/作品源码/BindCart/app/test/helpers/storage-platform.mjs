import { symlinkSync } from 'node:fs';

export const posixModes = {
  skip: process.platform === 'win32'
    ? 'POSIX 0600/0700 modes do not describe Windows ACLs; functional storage checks still run'
    : false,
};

export function createStorageLink(t, target, path, type = 'file') {
  // Directory junctions exercise Windows reparse-point rejection without
  // requiring the account's symbolic-link creation privilege.
  const linkType = process.platform === 'win32' && type === 'dir' ? 'junction' : type;
  try { symlinkSync(target, path, linkType); return true; }
  catch (error) {
    if (process.platform === 'win32' && linkType === 'file' && ['EPERM', 'EACCES', 'ENOSYS'].includes(error.code)) {
      t.skip(`File symlink fixture unavailable (${error.code}); rerun with Windows Developer Mode or symbolic-link privilege`);
      return false;
    }
    throw error;
  }
}
