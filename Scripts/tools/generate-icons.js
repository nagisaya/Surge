const fs = require("fs");
const path = require("path");

const iconsDir = path.join(__dirname, "../../Icons");
const baseURL = "https://raw.githubusercontent.com/nagisaya/Surge/main/Icons/";
const categories = ["Flag", "Shape", "Mark"];

for (const category of categories) {
  const directory = path.join(iconsDir, category);
  fs.mkdirSync(directory, { recursive: true });

  // Include nested PNGs, matching the workflow's Icons/**/*.png filter.
  function collectPNGs(dir, prefix = "") {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
      const relative = prefix + entry.name;
      if (entry.isDirectory()) {
        return collectPNGs(path.join(dir, entry.name), relative + "/");
      }
      return entry.isFile() && /\.png$/i.test(entry.name) ? [relative] : [];
    });
  }

  const files = collectPNGs(directory).sort();
  const icons = files.map(file => ({
    name: file.replace(/\.png$/i, ""),
    url: `${baseURL}${category}/${file.split("/").map(encodeURIComponent).join("/")}`
  }));
  const output = path.join(directory, "icons.json");
  const content = JSON.stringify({ name: `QVL ${category}`, icons }, null, 2) + "\n";

  // Only write categories whose manifest content changed.
  if (!fs.existsSync(output) || fs.readFileSync(output, "utf8") !== content) {
    fs.writeFileSync(output, content, "utf8");
    console.log(`Updated ${category}: ${icons.length} icons`);
  } else {
    console.log(`Unchanged ${category}: ${icons.length} icons`);
  }
}
