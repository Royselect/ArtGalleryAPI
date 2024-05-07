from .models import LogiFromMethods
from django.db import models
import requests
from bs4 import BeautifulSoup

def generate_report_file(filename, lines):
    with open(filename, 'w') as f:
        for line in lines:
            f.write(f"{line}\n")

def generate_report():
    method_stats = LogiFromMethods.objects.values('method_name').annotate(count=models.Count('id')).order_by('-count')

    # Формируем список строк отчета
    report_lines = ["Method Call Report:"]
    for method in method_stats:
        report_lines.append(f"{method['method_name']}: {method['count']}")

    # Генерируем отчет в виде txt-файла
    filename = "report.txt"
    generate_report_file(filename, report_lines)

