# Intake

Ask only what you do not already know from the request, the skill folder or
`$LOCAL`. Recommended option first. Two rounds at most; after that use the
defaults below and say which ones you used.

## Round 1 (always)

1. **Which skill and which repo name.** Path of the skill folder. Repo name
   default: `<skill-name>-skill` under the configured owner. Check the name is
   free: `gh repo view OWNER/NAME` must fail.
2. **What inside is not public.** Offer the likely categories you saw while
   reading the folder, multi-select: people and clients, an employer or a
   project of others, other private repos, code or text written by someone
   else, logos and brand material, real photos, real numbers (prices,
   ratings, accounts), local machine details. Each one selected becomes a
   line in the report inventory and, for names, a private term.
3. **Review depth.**
   - Complete (Recommended): automated gate, 2 to 4 security reviewers, a
     privacy and IP reviewer, a cold-start tester. Roughly 30 to 60 minutes.
   - Light: automated gate and one reviewer. Roughly 10 to 15 minutes.
   - Complete + benchmark: Complete plus with-and-without-skill evals.
4. **Launch extras**, multi-select: links in the README of the other public
   skills, an X post draft with infographic, a 9:16 short, nothing.

## Round 2 (only what is still open)

5. **Licence and holder.** Default MIT with the configured holder and the
   current year. Another licence only on request; never mix licences without
   saying so in the README.
6. **Other contributors.** Did anyone else write part of it? Their consent is
   needed to publish their work; credit them the way they want, or rewrite
   their part.
7. **Examples.** What the real examples become: fictional company and people
   (default), a public project with permission, or removed.
8. **Type specifics**, ask the ones that apply:
   - hardware: which boards and modules, voltages, whether mains or batteries
     are involved, whether photos of a real bench go in;
   - network: which services, which keys the user must bring, any server the
     skill starts;
   - generated pages: published where, which CDN scripts;
   - personal data: whose data the skill handles at run time.
9. **Language** of the public files. Default English; the skill still talks
   to its users in their language.

## Defaults when the owner says "you decide"

MIT, configured holder, repo `<skill-name>-skill`, Complete review, fictional
examples, English files, README cross-links only.

## Write down

Put every answer in the release report "Intake" section before step 2. If an
answer conflicts with `local.md`, `local.md` wins and you say so.
