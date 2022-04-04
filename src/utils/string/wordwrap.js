export default function wordwrap(str, width = 64) {
  if (!str) {
    return str;
  }
  const regex = "(.{1," + width + "})( +|$\n?)|(.{1," + width + "})";
  return str.match(RegExp(regex, "g")).join("\n");
}
