from fastapi import FastAPI, UploadFile, File, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse, JSONResponse
from jinja2 import FileSystemLoader
import shutil
import traceback # Indispensable pour voir l'erreur réelle
from pathlib import Path
import main 

app = FastAPI(title="SecretHunter v1.0")

UPLOAD_DIR = Path("uploads")
OUTPUT_DIR = Path("output")
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.loader = FileSystemLoader("templates")
templates.env.cache = None 

@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request, name="index.html", context={"request": request})

@app.post("/api/scan")
async def start_scan(file: UploadFile = File(...)):
    try:
        print(f"[*] Réception du fichier : {file.filename}")
        file_path = UPLOAD_DIR / file.filename
        
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        print(f"[*] Fichier sauvegardé. Lancement du moteur de scan...")
        
        # --- CORRECTION ICI : Ajout de await ---
        results = await main.run_web_scan(str(file_path))
        
        print(f"[*] Scan terminé. {len(results)} vulnérabilités trouvées.")
        
        return {
            "app_name": file.filename,
            "findings": results,
            "pdf_report_url": f"/api/download/{file_path.stem}"
        }
        
    except Exception as e:
        # TRÈS IMPORTANT : Ceci va afficher l'erreur exacte dans ton terminal
        print("\n" + "!"*30)
        print("ERREUR DÉTECTÉE DANS LE MOTEUR DE SCAN :")
        traceback.print_exc() 
        print("!"*30 + "\n")
        
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/download/{name}")
async def download_report(name: str):
    pdf_path = OUTPUT_DIR / f"Audit_Report_{name}.pdf"
    if pdf_path.exists():
        return FileResponse(pdf_path, media_type='application/pdf', filename=f"Audit_Report_{name}.pdf")
    return JSONResponse(status_code=404, content={"error": "PDF non trouvé"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)