# Documentation Media & Testbed Photographic Evidence

This directory stores visual evidence, physical lab testbed photography, and run-time screenshots collected during calibration and benchmarking for inclusion in the final technical report and presentation.

---

## Directory Organization

- **`testbed_photos/`**: High-resolution photographs of the physical testing environment:
  - Dual HP ProDesk 4 Tower workstations (DUT server `aiori-HP-ProDesk-4` and traffic generator `aiori-2-HP-ProDesk-4`).
  - Isolated physical Ethernet link (`eno1` direct-connect cable / dedicated switch).
  - Hardware setup, console monitors, and test execution in the lab.
- **`screenshots/`**: Console captures, performance monitoring, and terminal evidence:
  - `lab_pc2_calibration_screenshot.png`: Real-time traffic generation and calibration snapshot from PC 2 (`aiori-2-HP-ProDesk-4`) during initial saturation profiling.

---

## Usage in Documentation and Technical Reports

When referencing these images in Markdown or LaTeX documents:

### Markdown
```markdown
![Physical Testbed Setup](media/testbed_photos/testbed_setup.jpg)
![Calibration Run Screenshot](media/screenshots/lab_pc2_calibration_screenshot.png)
```

### LaTeX
```latex
\begin{figure}[htbp]
  \centering
  \includegraphics[width=0.85\linewidth]{docs/media/testbed_photos/testbed_setup.jpg}
  \caption{Physical Lab Testbed Environment: Dual HP ProDesk Workstations with Dedicated Gigabit Link.}
  \label{fig:testbed_photo}
\end{figure}
```
