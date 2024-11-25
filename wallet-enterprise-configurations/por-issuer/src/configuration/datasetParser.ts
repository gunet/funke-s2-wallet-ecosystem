import * as XLSX from 'xlsx';
import fs from 'fs';

export function parseDataset(filePath: string, sheetName: "PID" | "POR") {
	try {
		const readOpts: XLSX.ParsingOptions = {
			cellText: false, 
			cellDates: true,
			type: 'buffer'
		};
		const fileBuffer = fs.readFileSync(filePath);
	
		// Parse the workbook
		const workbook = XLSX.read(fileBuffer, readOpts);

		// Get the first worksheet
		const worksheet = workbook.Sheets[sheetName];

		// Convert worksheet to JSON format
		let data: any[] = XLSX.utils.sheet_to_json(worksheet, {
			defval: null,
			dateNF: 'd"/"m"/"yyyy'
			// skipHidden: true,
			// header: 0
		});
	
		if (data.length == 0) {
			throw new Error("Empty dataset");
		}


		data = data.map((row) => {
			return {
				...row,
			}
		});

		data.shift(); // remove the first element which indicates if field is mandatory or not

		return data;
	}
	catch(err) {
		console.error(err);
		return null;
	}

}