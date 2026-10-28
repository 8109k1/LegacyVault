function togglePassword(id){const el=document.getElementById(id);if(el)el.type=el.type==="password"?"text":"password";}
function demoLogin(e){e.preventDefault();window.location.href="dashboard.html";}
function demoRegister(e){e.preventDefault();alert("Demo: registration successful!");window.location.href="login.html";}

function filterTable() {
  const searchInput = document.getElementById("docSearch");
  const table = document.getElementById("documentsTable");

  if (!searchInput || !table) return;

  const query = searchInput.value.trim().toLowerCase();
  const rows = table.querySelectorAll("tbody tr");
  let visibleCount = 0;

  rows.forEach((row) => {
    const matches = row.textContent.toLowerCase().includes(query);

    row.style.display = matches ? "" : "none";

    if (matches) visibleCount++;
  });

  // Show a message when no documents match.
  let emptyMessage = document.getElementById("noSearchResults");

  if (!emptyMessage) {
    emptyMessage = document.createElement("p");
    emptyMessage.id = "noSearchResults";
    emptyMessage.textContent = "No documents found. Try another search.";
    emptyMessage.style.display = "none";
    table.insertAdjacentElement("afterend", emptyMessage);
  }

  emptyMessage.style.display =
    rows.length > 0 && visibleCount === 0 ? "block" : "none";
}

function openModal(){document.getElementById("beneficiaryModal")?.classList.add("show")}
function closeModal(){document.getElementById("beneficiaryModal")?.classList.remove("show")}
function saveBeneficiary(){closeModal();alert("Demo: beneficiary added successfully!")}
function openMessageModal(){document.getElementById("messageModal")?.classList.add("show")}
function closeMessageModal(){document.getElementById("messageModal")?.classList.remove("show")}
function saveMessage(){closeMessageModal();alert("Demo: message saved successfully!")}
