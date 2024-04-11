## Github

### Links
- [Github Dump Tool](https://github.com/arthaud/git-dumper)
- [Github Commit History](https://www.howtogeek.com/devops/how-to-view-commit-history-with-git-log/)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [GitKraken](https://www.gitkraken.com/download)
- [Insecure Source Code Management Payload All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Source%20Code%20Management/#gogitdumper)

GIT Commit Dump - whenever you see some github files on the Victim machine, Exfiltrate it and refer to the following resources


### Git Dump

```
For example:
git-dumper http://192.168.232.144/.git/ TheGit


Then run gitkraken gui on it to see file change history

or maybe run TruffleHog on it:

trufflehog git https://github.com/trufflesecurity/test_keys --only-verified



```