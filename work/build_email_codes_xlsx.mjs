import fs from "node:fs/promises";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const rootDir = "C:/Users/Alex/Documents/Codex/2026-07-10/new-chat";
const inputPath = `${rootDir}/outputs/icloud-email-code-pairs.txt`;
const outputPath = `${rootDir}/outputs/icloud-email-codes.xlsx`;
const previewPath = `${rootDir}/work/icloud-email-codes-preview.png`;

const text = await fs.readFile(inputPath, "utf8");
const rows = text
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter(Boolean)
  .map((line) => {
    const [email, rawCode] = line.split(":");
    return [email, rawCode.replace(/^\*\*|\*\*$/g, "")];
  });

const workbook = Workbook.create();
const sheet = workbook.worksheets.add("Email Codes");
sheet.showGridLines = false;

sheet.getRange("A1:B1").values = [["email", "code"]];
sheet.getRangeByIndexes(1, 0, rows.length, 2).values = rows;

sheet.getRange("A1:B1").format = {
  fill: "#1F4E78",
  font: { bold: true, color: "#FFFFFF" },
};
sheet.getRange(`A1:B${rows.length + 1}`).format.borders = {
  preset: "all",
  style: "thin",
  color: "#D9E2F3",
};
sheet.getRange(`A2:B${rows.length + 1}`).format = {
  font: { color: "#111827" },
};
sheet.getRange("A:A").format.columnWidth = 34;
sheet.getRange("B:B").format.columnWidth = 18;
sheet.getRange(`A1:B${rows.length + 1}`).format.wrapText = false;
sheet.freezePanes.freezeRows(1);

const inspect = await workbook.inspect({
  kind: "table",
  range: `Email Codes!A1:B${rows.length + 1}`,
  include: "values",
  tableMaxRows: 12,
  tableMaxCols: 2,
});
console.log(inspect.ndjson);

const errors = await workbook.inspect({
  kind: "match",
  searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A",
  options: { useRegex: true, maxResults: 20 },
});
console.log(errors.ndjson);

const preview = await workbook.render({
  sheetName: "Email Codes",
  range: `A1:B${rows.length + 1}`,
  scale: 2,
  format: "png",
});
await fs.writeFile(previewPath, new Uint8Array(await preview.arrayBuffer()));

const output = await SpreadsheetFile.exportXlsx(workbook);
await output.save(outputPath);
console.log(`saved ${outputPath}`);
