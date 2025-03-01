document.getElementById("checkButton").addEventListener("click", async () => {
  let urlInput = document.getElementById("urlInput").value.trim();
  if (!urlInput) {
    alert("Please enter a URL.");
    return;
  }

  urlInput = urlInput.replace(/^https?:\/\/(www\.)?/, "https://");

  document.getElementById("loading").style.display = "flex";
  document.getElementById("result").style.display = "none";

  try {
    const response = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlInput }),
    });

    const data = await response.json();

    const resultText = document.getElementById("resultText");
    if (data.is_phishing) {
      resultText.textContent = "⚠️ This URL is likely a phishing site.";
      resultText.style.color = "#e74c3c";
    } else {
      resultText.textContent = "✅ This URL is safe to visit.";
      resultText.style.color = "#2ecc71";
    }
  } catch (error) {
    console.error("Error:", error);
    document.getElementById("resultText").textContent =
      "An error occurred. Please try again.";
    document.getElementById("resultText").style.color = "#e74c3c";
  } finally {
    document.getElementById("loading").style.display = "none";
    document.getElementById("result").style.display = "block";
  }
});
