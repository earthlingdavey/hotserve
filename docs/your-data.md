# Your data

An app keeps what must last in `shared/`:
`/var/lib/liveswap/<app>/shared` on the box. hotserve never deletes it,
and that is all it does for it. **No stable release of hotserve backs
up your data: today that is your job.** This page says what survives
what, gives you a copy you can put back, and states the rule every
migration has to follow.

Names: an app called `blog` with its database at `shared/app.db`, on
`box.example.com`. Commands run as root on the box unless they say
otherwise. Those that touch the app's files run as `hotserve`, through
`runuser`, so nothing in `shared/` ends up root's and out of the app's
reach. Change `blog` and `app.db` everywhere before you paste. Most
blocks stop on a wrong name, but those that put a file in place cannot
tell, and print `in place` anyway.

## What survives what

| Event | `shared/` | Release dirs | The app's `/tmp` | What else |
|---|---|---|---|---|
| A deploy | Kept; `pre_start` runs on it | A new one beside the others | Empty for the new version | The old version serves until the cutover |
| A deploy that fails | Kept, **with whatever `pre_start` did to it**, if it got that far | The failed one removed | The old version's, kept | The old version keeps serving, on the migrated schema if `pre_start` ran |
| A rollback | Kept and not touched: nothing is undone | Kept | Empty | An on-disk release relaunched, with no `pre_start` |
| A watchdog restart | Kept | Kept | Empty | The same version, with no `pre_start` |
| `systemctl restart hotserve`, or an upgrade | Kept | Kept | Kept | The app is not relaunched: the same process goes on |
| A reboot | Kept | Kept | Empty | The current version relaunched, with no `pre_start` |
| `keep` pruning, after a successful deploy | Kept | All but the `keep` newest removed (five by default) | Untouched | A rollback to a removed one is a 422 |
| `apt remove hotserve` | Kept | Kept | Gone | The apps stop. `/etc/hotserve` is kept. Install again, then `systemctl enable --now hotserve`, and the current version comes back |
| `apt purge hotserve` | Kept | Kept | Gone | The Caddyfile goes. Kept, and named as it purges: the box's key and env files in `/etc/hotserve`. Also kept: the TLS certificates in `/var/lib/hotserve` and the `hotserve` user |
| Rebuilding the server | **Gone** | **Gone** | Gone | What comes back is what you copied off, plus the Caddyfile and secrets from [the box's repository](secrets.md#a-rebuilt-box). Not in it: [a local key or a hand-made env file](#get-it-off-the-box) |

So keep nothing you need in the release dir, though the app can write
there: it goes when the release is pruned, and no other version sees
it. Keep nothing you need in `/tmp`. No package step deletes
`/var/lib/liveswap`. To be rid of it, `rm -r` it yourself.

## No stable release backs up your data

hotserve runs on one server, so your data is on one disk. A dead disk,
a closed provider account, a stray `rm` or a bug in the app takes it,
and nothing brings it back unless you made a copy somewhere else.

- A copy on the same box helps with a mistake. It does not help when
  the box is gone.
- A copy of bad data is bad data. Keep several, dated, or a bug you
  notice on Friday has already overwritten Monday.
- How often you copy is how much you can lose.
- A provider's disk snapshot is worth having, but it sits in the same
  account and holds the box's key and env files
  ([A box cloned from a snapshot](secrets.md#a-box-cloned-from-a-snapshot)).

## A SQLite file in `shared/`

### Copy it

A box may have only the library, not the `sqlite3` program:
`command -v sqlite3` prints nothing. Install it, and make a directory
for the copies. It is outside every app's sandbox view:

```sh
apt install sqlite3
install -d -m 0700 -o hotserve -g hotserve /var/backups/blog
```

Then copy, with the app running. This works under WAL and under a
writer:

```sh
db=/var/lib/liveswap/blog/shared/app.db; out=/var/backups/blog/app.db
rm -f $out.new &&
  runuser -u hotserve -- sqlite3 -cmd '.timeout 30000' "file:$db?mode=rw" "VACUUM INTO '$out.new'" &&
  [ "$(runuser -u hotserve -- sqlite3 "file:$out.new?mode=ro" 'PRAGMA integrity_check')" = ok ] &&
  mv $out.new $out && echo backed up ||
  { rm -f $out.new $out.new-journal; echo "no copy made: the last good one stays" >&2; false; }
```

```
backed up
```

The `&&`s stop at the first step that fails, the last good copy stays
in place, and the partial file goes: left on the app's disk, it would
keep the app's own writes failing (measured). It needs about the
database's size free on that disk.

Why this and not something shorter:

- **Not `cp`.** Under WAL, recent writes are in `app.db-wal`, and a
  `cp` of the file misses them. With a writer running and checkpoints
  off, a `cp` held 0 rows of 1,083 (measured).
- **Not `.backup`.** It starts again whenever another connection
  writes. On 300 MB with a writer at 100 transactions a second, it had
  not finished after 120 seconds, where `VACUUM INTO` had (measured).
- **`mode=rw`** makes a wrong path an error. Without it, `sqlite3`
  makes an empty database there, and `integrity_check` calls that `ok`.

Under WAL the writer carries on during the copy. In SQLite's default
rollback-journal mode, writers are locked out for the copy: one with a
busy timeout waits, and one without gets `database is locked`.

Check that it holds your data, not only that it is sound, with a table
of your own. The block cannot tell: a database the app has recreated
empty passes, and replaces the last good copy (measured), so keep
several:

```sh
runuser -u hotserve -- sqlite3 /var/backups/blog/app.db 'SELECT count(*) FROM posts'
```

**A second database in `shared/` is not a plain file.** Under writes,
`tar` archived one corrupt while this block said `files copied`
(measured). Give it a copy block of its own, and add it to the
`--exclude`s.

Anything else there, uploads say, is plain files. This leaves the
database out, since the block above has it:

```sh
runuser -u hotserve -- tar -C /var/lib/liveswap/blog/shared --exclude=./app.db --exclude='./app.db-*' -czf /var/backups/blog/files.tar.gz.new . ; [ $? -le 1 ] &&
  mv /var/backups/blog/files.tar.gz.new /var/backups/blog/files.tar.gz && echo files copied ||
  { rm -f /var/backups/blog/files.tar.gz.new; false; }
```

```
files copied
```

`tar` exits 1 for a file that changed as it read, which a running app
causes. That file may be partial, and the rest of the archive is whole.
A worse error is 2 and stops it.

### Get it off the box

From your laptop, or any machine that is not the box:

```sh
t=$(date +%F-%H%M%S)
scp root@box.example.com:/var/backups/blog/app.db blog-$t.db
scp root@box.example.com:/var/backups/blog/files.tar.gz blog-files-$t.tar.gz
ssh root@box.example.com sha256sum /var/backups/blog/app.db
sha256sum blog-$t.db                 # the same sum as the line above
```

The copy is your data in the clear: keep it as you keep the box.

Two things the box's repository does not hold, so copy them off too. A
`deploy_trust local` public key file: `hotserve init` refuses a
Caddyfile whose key file is missing. An env file made by hand: a launch
that reads a missing one fails, so
[move it in](secrets.md#move-a-hand-made-env-file-in) or copy it.

To repeat it, put the copy in a script on the box:

```sh
cat > /usr/local/sbin/copy-blog <<'EOF'
#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
db=/var/lib/liveswap/blog/shared/app.db; out=/var/backups/blog/app.db
rm -f $out.new &&
  runuser -u hotserve -- sqlite3 -cmd '.timeout 30000' "file:$db?mode=rw" "VACUUM INTO '$out.new'" &&
  [ "$(runuser -u hotserve -- sqlite3 "file:$out.new?mode=ro" 'PRAGMA integrity_check')" = ok ] &&
  mv $out.new $out || { rm -f $out.new $out.new-journal; echo "no copy made: the last good one stays" >&2; exit 1; }
runuser -u hotserve -- tar -C /var/lib/liveswap/blog/shared --exclude=./app.db --exclude='./app.db-*' -czf /var/backups/blog/files.tar.gz.new . ; [ $? -le 1 ] &&
  mv /var/backups/blog/files.tar.gz.new /var/backups/blog/files.tar.gz || { rm -f /var/backups/blog/files.tar.gz.new; exit 1; }
EOF
chmod 0700 /usr/local/sbin/copy-blog
```

And on the other machine, a script run from a directory for this app's
copies alone, since it prunes by name. It names a fetch only once the copy and the fetch have both worked, so a
stale or cut-off copy never gets a fresh name, and it keeps the newest
30:

```sh
#!/bin/sh
t=$(date +%F-%H%M%S)
rm -f blog-*.db.new blog-files-*.tar.gz.new
ssh root@box.example.com /usr/local/sbin/copy-blog &&
  scp -q root@box.example.com:/var/backups/blog/app.db blog-$t.db.new &&
  scp -q root@box.example.com:/var/backups/blog/files.tar.gz blog-files-$t.tar.gz.new &&
  [ -s blog-$t.db.new ] &&
  mv blog-$t.db.new blog-$t.db && mv blog-files-$t.tar.gz.new blog-files-$t.tar.gz || exit 1
ls -1t blog-*.db | tail -n +31 | xargs -r rm --
ls -1t blog-files-*.tar.gz | tail -n +31 | xargs -r rm --
```

Run it from cron with `cd` first. A bare `%` on a crontab line ends the
command, so keep the dates in the script. That machine holds root's
key, and can take the box, so choose it with that in mind. Nothing here
tells you when it stops: check the newest copy's date.

### Put it back

You cannot stop the app first: its watchdog relaunches it. You do not
need to. SQLite's `.restore` replaces the database in one transaction
with the app running. Everything written since the copy is lost.

**A copy brings back the schema it was taken on,** and its
`user_version`, under the version running now, and no `pre_start` runs.
So before you restore, roll back to a version that works on that
schema. Afterwards go forward with new versions, whose `pre_start`
migrates it. Deploying the version already there runs no `pre_start`.
A version that merely reads the old schema is not enough: [the
migration rule](#the-migration-rule) shows why.

Bring the copy to `/root/restore.db`. From the laptop:

```sh
scp blog-2026-10-30-030000.db root@box.example.com:/root/restore.db
scp blog-files-2026-10-30-030000.tar.gz root@box.example.com:/root/files.tar.gz
```

Or, for the copy already on the box, `cp /var/backups/blog/app.db
/root/restore.db`. Do that first: the copy block overwrites that file.

Then keep what is there now, under a name of its own. This is your way
back. If it stops because the live database is damaged, go on without it:

```sh
db=/var/lib/liveswap/blog/shared/app.db; out=/var/backups/blog/before-restore-$(date +%F-%H%M%S).db
rm -f $out.new &&
  runuser -u hotserve -- sqlite3 -cmd '.timeout 30000' "file:$db?mode=rw" "VACUUM INTO '$out.new'" &&
  [ "$(runuser -u hotserve -- sqlite3 "file:$out.new?mode=ro" 'PRAGMA integrity_check')" = ok ] &&
  mv $out.new $out && echo backed up ||
  { rm -f $out.new $out.new-journal; false; }
```

Then restore:

```sh
db=/var/lib/liveswap/blog/shared/app.db; src=/var/backups/blog/restore.db
[ -s /root/restore.db ] &&
  install -m 0600 -o hotserve -g hotserve /root/restore.db $src &&
  [ "$(runuser -u hotserve -- sqlite3 "file:$src?mode=ro" 'PRAGMA integrity_check')" = ok ] &&
  runuser -u hotserve -- sqlite3 -cmd '.timeout 30000' "file:$db?mode=rw" ".restore file:$src?mode=ro" &&
  echo restored
```

```
restored
```

A missing, empty or truncated file stops it, and the live database is
untouched (measured). Without the `&&`s, `.restore` of a missing file
restores an empty database over your data. Check the result:

```sh
runuser -u hotserve -- sqlite3 'file:/var/lib/liveswap/blog/shared/app.db?mode=rw' 'PRAGMA integrity_check; SELECT count(*) FROM posts'
```

```
ok
3000
```

The way back is `cp` of the `before-restore-` file to
`/root/restore.db`, then the restore block again.

A writer with a busy timeout waits and carries on: 7 seconds for 300 MB
(measured). One without can get `database is locked` for that long. The
database keeps its WAL mode. `Error: source database is busy` means a
writer held its lock past the timeout: nothing changed (measured), so
run it again.

The app's open connections see the restored data at their next read,
but what it holds in memory stays. To clear that, give it a fresh
launch: [roll back to the running
version](../liveswap/README.md#relaunching-the-running-version).

Files go back over what is there, and anything the copy does not hold
stays:

```sh
runuser -u hotserve -- tar -C /var/lib/liveswap/blog/shared -xzf - < /root/files.tar.gz
```

### When the database is gone or will not open

`.restore` needs a live file it can open. If the file is gone or its
header is damaged, it fails with `unable to open database file` or
`file is not a database`, and changes nothing. (Damage further in does
not stop it: use the block above.) Move the file aside with its
companions, and restore into what is left. The copy goes in through
SQLite's locks, not over the file: with an app opening the database for
each write, an `install` over it printed `in place` and left an empty
database (measured).

```sh
db=/var/lib/liveswap/blog/shared/app.db; src=/var/backups/blog/restore.db; aside=/var/backups/blog/damaged-$(date +%F-%H%M%S)
[ -s /root/restore.db ] &&
  install -m 0600 -o hotserve -g hotserve /root/restore.db $src &&
  [ "$(runuser -u hotserve -- sqlite3 "file:$src?mode=ro" 'PRAGMA integrity_check')" = ok ] &&
  install -d -m 0700 -o hotserve -g hotserve $aside &&
  { find "${db%/*}" -maxdepth 1 \( -name "${db##*/}" -o -name "${db##*/}-*" \) -exec mv -t $aside {} + ; true; } &&
  runuser -u hotserve -- sqlite3 -cmd '.timeout 30000' "$db" ".restore file:$src?mode=ro" &&
  echo in place
```

```
in place
```

A `mv: cannot stat` about a companion the app has just removed does no
harm. Under a busy app this can stop with `Error: disk I/O error` or
`source database is busy`, with the copy in place or not (measured):
check the result as above, and run it again if it is not there. Then [roll back to the running
version](../liveswap/README.md#relaunching-the-running-version) at
once: the running instance may still have the old file open, and until
it relaunches it reports success for writes that go to the moved file,
not the restored one (measured). A corrupt
database fails its next launch too, so this is the way back from one.
The copy is in rollback-journal mode, so an app that wants WAL sets it
when it opens the database.

### On a new box

Install hotserve, put back a `deploy_trust local` key if you have one,
and run `hotserve init`, as the first deploy did. Bring the secrets
back ([A rebuilt box](secrets.md#a-rebuilt-box)). `apt install sqlite3`.
**Before the app's first deploy**, with the copies at `/root/restore.db`
and `/root/files.tar.gz`. It stops if the app already has a database:

```sh
[ -s /root/restore.db ] && [ ! -e /var/lib/liveswap/blog/shared/app.db ] &&
  [ "$(sqlite3 'file:/root/restore.db?mode=ro' 'PRAGMA integrity_check')" = ok ] &&
  install -d -m 0750 -o hotserve -g hotserve /var/lib/liveswap/blog /var/lib/liveswap/blog/shared &&
  runuser -u hotserve -- tar -C /var/lib/liveswap/blog/shared -xzf - < /root/files.tar.gz &&
  install -m 0640 -o hotserve -g hotserve /root/restore.db /var/lib/liveswap/blog/shared/app.db &&
  echo in place
```

Then deploy by pushing a commit: the old releases are gone, so a
rollback has nothing to relaunch. Its `pre_start` runs on the restored
file, which is why a migration has to be safe to run again.

## The migration rule

**Every migration must work with the previous version.** That version
serves on the new schema during the soak, and again after a rollback.

Here is why, from [how a deploy
works](../liveswap/README.md#how-a-deploy-works):

- `pre_start` runs while the old version is serving. From then on, the
  old version is on the new schema.
- During the soak both run, and both can read and write.
- A deploy that fails after `pre_start` leaves the old version serving
  on the new schema until your next deploy. A `pre_start` that exits
  non-zero leaves whatever it did: wrap it in a transaction.

**What a rollback does:** it starts the old release, gates it on
`/health` and cuts over. **What it does not do:** run `pre_start`, undo
a migration, touch the database, or bring back anything since deleted.
The old code meets the new schema and the rows the new code wrote.
hotserve cannot see your schema, so it refuses nothing on that account.
An old version that answers `/health` and then fails its queries gets
promoted.

So add first, and remove later. Here is `users.email` renamed to
`email_address`, one release at a time. Each release's migration is
safe for the one before it:

| Release | `pre_start` | The code | Rollback is safe to |
|---|---|---|---|
| v2, expand | `ALTER TABLE users ADD COLUMN email_address TEXT;` and `UPDATE users SET email_address = email WHERE email_address IS NULL;` | Writes both; reads `COALESCE(email_address, email)` | v1 (below) |
| v3 | `UPDATE users SET email_address = email WHERE email_address IS NOT email;` | Writes both; reads `email_address` | v2; v1 only if v4 never ran (below) |
| v4 | None | Writes and reads `email_address` only | v3, v2. Never v1, directly or through v2 or v3: it reads `NULL` for v4's rows and the old value for those v4 changed |
| v5, contract | `ALTER TABLE users DROP COLUMN email;` | As v4 | v4 only |

v3's `UPDATE` fixes rows v1 changed during v2's soak, which v2 reads
stale until then, as well as those it added. If you roll back to v1,
its writes miss `email_address`, and a rollback to v2 or v3 runs no
`pre_start`. Go forward with v2's code in a new release, then v3's in
another, whose `pre_start` runs that `UPDATE`, as a step of its own if
`user_version` says v3's has run. One release straight from v1 leaves v1
writing through its soak, after the `UPDATE` has run.

Never run it once v4 has been live: `email` is stale by then and `NULL`
on v4's own rows, so it would undo changes and erase addresses. A
restore can run it by accident: a copy from before v3 comes back with a
`user_version` below v3's, and the next `pre_start` applies it over
whatever v4 has written since. So roll back to v3, restore, then deploy
v3's code as a new release, so its `pre_start` runs the `UPDATE` before
v4 goes live. Going straight on to v4, which has no `pre_start`, leaves
the `UPDATE` waiting for v5, and it erases v4's addresses (measured).
Until that release, rows v1 changed or added in v2's soak read stale or
`NULL`, so deploy it first. A
copy from before v2 has no `email_address`: it needs a release that
reads v1's schema first.

This assumes a plain nullable column. If `email` is `NOT NULL`, v4's
inserts fail once it is live. If it is `UNIQUE` or indexed, SQLite
refuses v5's `DROP`. Either needs a table rebuild
([SQLite's steps](https://www.sqlite.org/lang_altertable.html#otheralter))
in a release of its own.

A single `ALTER TABLE users RENAME COLUMN email TO email_address;`
looks tidier, and the old version's next write fails:

```
Error: in prepare, table users has no column named email
```

v3 gets the same error if you roll back to it from v5. So contract
only once nothing you would roll back to uses the column. A rollback
reaches any release still on disk, the newest `keep` (five by default),
and hotserve starts any of them.

A migration also has to be safe to run again, since a retried deploy
runs it again. SQLite refuses a second `ADD COLUMN` (`duplicate column
name`), so keep a version number and skip what has been applied. Keep
it in the database, with `PRAGMA user_version`, so a restore brings it
back with the schema: a number in a file of its own would say migrated
over a restored older database, and the next `pre_start` would skip the
migration. The example's `migrate.js` shows the skip, with a file
because it has no database.

If a change cannot be made compatible, say so to yourself before you
push it, and take a copy first. The way back from such a change is that
copy and an older release, and it loses every write since.
