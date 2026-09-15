export function processMkDocsAdmonitions(md: string): string {
  const lines = md.split("\n");
  const result: string[] = [];

  let i = 0;
  while (i < lines.length) {
    const match = lines[i].match(
      /^!!!\s+(note|tip|warning|danger|deprecated|info)\s*(?:"([^"]+)")?\s*$/i,
    );
    if (match) {
      const type = match[1].toLowerCase();
      const title = match[2];
      const bodyLines: string[] = [];
      i++;
      while (i < lines.length && (lines[i].startsWith("    ") || lines[i].trim() === "")) {
        bodyLines.push(lines[i].replace(/^    /, ""));
        i++;
      }
      result.push(title ? `:::${type}[${title}]` : `:::${type}`);
      result.push(...bodyLines);
      result.push(":::");
      continue;
    }
    result.push(lines[i]);
    i++;
  }

  return result.join("\n");
}
