#!/bin/bash


BACKEND_DIR="arabguard-backend"
FRONTEND_DIR="arabguard-dashboard"

echo "🚀 Starting ArabGuard Project..."

echo "📡 Starting Backend (FastAPI)..."
cd $BACKEND_DIR

uvicorn main:app --reload --port 8000 &
BACKEND_PID=$!

cd ..

echo "💻 Starting Frontend (Vite)..."
cd $FRONTEND_DIR
npm run dev &
FRONTEND_PID=$!

echo "---------------------------------------"
echo "✅ ArabGuard is running!"
echo "🔗 Frontend: http://localhost:3000 (check your vite port)"
echo "🔗 Backend Docs: http://localhost:8000/docs"
echo "💡 Press [CTRL+C] to stop both servers."
echo "---------------------------------------"

cleanup() {
    echo -e "\n🛑 Stopping servers..."
    kill $BACKEND_PID
    kill $FRONTEND_PID
    echo "👋 Done. See you soon!"
    exit
}

trap cleanup SIGINT

wait