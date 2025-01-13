import * as fs from 'fs';
import * as path from 'path';

export async function generateSBOM(scanResults: any): Promise<string> {
    const sbomPath = path.join(process.cwd(), 'sbom.spdx.json');

    const sbomContent = {
        version: "1.0",
        SPDXID: "SPDXRef-DOCUMENT",
        name: "ScanOSS SBOM",
        description: "Generated Software Bill of Materials (SBOM)",
        packages: scanResults.map((result: any) => ({
            name: result.componentName,
            version: result.version,
            licenses: result.licenses,
            vulnerabilities: result.vulnerabilities || [],
        })),
    };

    fs.writeFileSync(sbomPath, JSON.stringify(sbomContent, null, 2));
    return sbomPath;
}
