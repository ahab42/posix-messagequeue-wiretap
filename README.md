# POSIX Message queue wiretap

`LD_PRELOAD` hook to monitor POSIX message queue ineractions in an application.

```
app:    mq_open(...)
hook:   ->  mq_open_hook(...)
hook:       ->  rax = mq_open(); send arguments and return values to TCP address on a different thread
hook:       <- return rax
hook:   <- return rax
app:   rax
```

## Usage

Compile to your target's GLIBC , change value of `target` in Makefile.
