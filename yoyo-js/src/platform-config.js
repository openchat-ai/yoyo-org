'use strict';

const TEXT_VS = 0x8000;
const CODE_RVA = 0x1000;
const DATA_RVA = CODE_RVA + TEXT_VS;
const STATE_TARGET = 0xfb;
const STATE_BUF_OFF = 0x8000;
const OUTPUT_STATE_BUF_OFF = 0x1000;
const ELF_TEXT_FILE_OFF = 0x1000;
const PE_TEXT_FILE_OFF = 0x400;

const WIN_FUNCS = [
  'ExitProcess', 'GetStdHandle', 'WriteFile', 'ReadFile',
  'CreateFileA', 'GetFileSize', 'CloseHandle', 'VirtualAlloc',
  // libyoyo_* (Phase 4c) - imported from libyoyo.dll (or libyoyo.a static)
  'libyoyo_alloc', 'libyoyo_free', 'libyoyo_open', 'libyoyo_read',
  'libyoyo_write', 'libyoyo_close', 'libyoyo_exit', 'libyoyo_print',
  'libyoyo_time',
];

const LINUX_SYSCALL = {
  read: 0,
  write: 1,
  open: 2,
  close: 3,
  mmap: 9,
  exit: 60,
};

const O_RDONLY = 0;
const O_WRONLY = 1;
const O_CREAT = 64;
const O_TRUNC = 512;

module.exports = {
  TEXT_VS,
  CODE_RVA,
  DATA_RVA,
  STATE_TARGET,
  STATE_BUF_OFF,
  OUTPUT_STATE_BUF_OFF,
  ELF_TEXT_FILE_OFF,
  PE_TEXT_FILE_OFF,
  WIN_FUNCS,
  LINUX_SYSCALL,
  O_RDONLY,
  O_WRONLY,
  O_CREAT,
  O_TRUNC,
};
