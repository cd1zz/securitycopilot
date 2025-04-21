import logging
import azure.functions as func
import markdown
from weasyprint import HTML
import io

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(methods=["POST"], route="")
def convert_markdown_pdf(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing Markdown to PDF conversion.")

    try:
        markdown_text = req.get_body().decode("utf-8")
        if not markdown_text:
            return func.HttpResponse("Empty markdown content.", status_code=400)

        # Convert Markdown to HTML with table support
        body_html = markdown.markdown(markdown_text, extensions=['tables'])

        # Wrap in styled HTML template
        full_html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: sans-serif; font-size: 14px; }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 1em 0;
                }}
                th, td {{
                    border: 1px solid #ccc;
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #f9f9f9;
                }}
            </style>
        </head>
        <body>{body_html}</body>
        </html>
        """

        # Convert to PDF
        pdf_io = io.BytesIO()
        HTML(string=full_html).write_pdf(target=pdf_io)
        pdf_bytes = pdf_io.getvalue()

        return func.HttpResponse(
            body=pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=output.pdf"},
            status_code=200
        )

    except Exception as e:
        logging.error(f"Error during conversion: {e}")
        return func.HttpResponse("Internal Server Error", status_code=500)

